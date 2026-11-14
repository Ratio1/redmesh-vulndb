"""Build diff, lost-CVE check against an allow-list, and the offline gates T1-T4.

Gates run on a built database. T1 vulhub recall, T2 first-fixed bounds do not fire, T3 a version above
the maximum bound gives 0 findings, T4 the matcher cases. The reader-latency gate belongs to RM-169 Phase 2.
"""
import json
import re
import sqlite3
from collections import Counter
from pathlib import Path

from .build import DDL, MODEL, band
from .versions import _matches_constraint, _parse_version

def expected_columns():
  """{table: [columns]} from the one schema definition, build.DDL."""
  db = sqlite3.connect(":memory:")
  db.executescript(DDL)
  return {t: [c[1] for c in db.execute(f"PRAGMA table_info({t})")] for (t,) in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def connect(path):
  return sqlite3.connect(f"file:{path}?mode=ro", uri=True)


def pairs(db):
  return {tuple(r) for r in db.execute("SELECT DISTINCT product, cve_id FROM affected")}


def baseline_pairs(path):
  """The (product, cve) pairs of a previous build, with the connection closed."""
  db = connect(path)
  try:
    return pairs(db)
  finally:
    db.close()


def baseline_cves(path):
  """Every CVE id (either state) of a previous build: the tombstone candidates for the next build."""
  db = connect(path)
  try:
    return {r[0] for r in db.execute("SELECT cve_id FROM vuln")}
  finally:
    db.close()


def read_allowlist(path):
  """TSV `product<TAB>cve_id<TAB>reason`; `*` as product matches any product. `#` starts a comment."""
  out = {}
  for line in Path(path).read_text().splitlines():
    if line.strip() and not line.startswith("#"):
      product, cve, reason = (line.split("\t") + ["", "", ""])[:3]
      if not reason.strip():
        raise ValueError(f"allow-list line without a reason: {line!r}")
      out[(product.strip(), cve.strip())] = reason.strip()
  return out


def lost_pairs(baseline, new, allow):
  """Split the (product, cve) pairs of `baseline` missing from `new` into allowed (with reason) and unlisted."""
  allowed, unlisted = [], []
  for p, c in sorted(baseline - new):
    reason = allow.get((p, c)) or allow.get(("*", c))
    (allowed.append([p, c, reason]) if reason else unlisted.append([p, c]))
  return {"allowed": allowed, "unlisted": unlisted}


def diff_dbs(old_path, new_path):
  """Per-product pair delta, KEV changes, display severity band changes, schema change between two builds."""
  old, new = connect(old_path), connect(new_path)
  po, pn = pairs(old), pairs(new)
  by_product, old_counts = {}, Counter(p for p, _ in po)
  for p, c in po - pn:
    by_product.setdefault(p, {"old": old_counts[p], "added": 0, "removed": 0})["removed"] += 1
  for p, c in pn - po:
    by_product.setdefault(p, {"old": old_counts[p], "added": 0, "removed": 0})["added"] += 1
  vo = {r[0]: r[1:] for r in old.execute("SELECT cve_id, kev, display_cvss_score FROM vuln")}
  vn = {r[0]: r[1:] for r in new.execute("SELECT cve_id, kev, display_cvss_score FROM vuln")}
  common = vo.keys() & vn.keys()
  meta = lambda db: dict(db.execute("SELECT k, v FROM meta"))  # noqa: E731
  mo, mn = meta(old), meta(new)
  old.close()
  new.close()
  return {
    "old_build": mo.get("build_id"), "new_build": mn.get("build_id"),
    "schema_changed": mo.get("schema") != mn.get("schema"),
    "pairs": {"old": len(po), "new": len(pn), "added": len(pn - po), "removed": len(po - pn)},
    "by_product": dict(sorted(by_product.items())),
    "kev_added": sorted(c for c in common if vn[c][0] and not vo[c][0]) + sorted(c for c in vn.keys() - vo.keys() if vn[c][0]),
    "kev_removed": sorted(c for c in common if vo[c][0] and not vn[c][0]),
    "band_changes": sorted([c, band(vo[c][1]), band(vn[c][1])] for c in common if band(vo[c][1]) != band(vn[c][1])),
  }


def overlay_pairs(root):
  return {(r["product"], r["cve_id"]) for r in json.loads((Path(root) / "overlay/curated.json").read_text())["rows"]}


def _fires(db, product, version, cve):
  return any(_matches_constraint(version, c, product) for (c,) in db.execute(
    'SELECT "constraint" FROM affected WHERE product=? AND cve_id=?', (product, cve)))


def gate_integrity(db):
  res = db.execute("PRAGMA integrity_check").fetchall()
  return {"ok": res == [("ok",)], "detail": [r[0] for r in res][:5]}


def gate_schema(db):
  problems = []
  if db.execute("PRAGMA user_version").fetchone()[0] != MODEL:
    problems.append("user_version")
  for table, cols in expected_columns().items():
    got = [c[1] for c in db.execute(f"PRAGMA table_info({table})")]
    if got != cols:
      problems.append(f"{table}: {got}")
  meta = dict(db.execute("SELECT k, v FROM meta")) if not problems else {}
  for key in ("schema", "build_id", "matcher_rev"):
    if not meta.get(key) and not problems:
      problems.append(f"meta.{key}")
  return {"ok": not problems, "detail": problems}


def gate_t1(db, golden):
  """Vulhub recall from the vendored EXPECT list, and the 9 prototype regressions fixed through the overlay."""
  expect = json.loads((Path(golden) / "vulhub_expect.json").read_text())
  dead = set(expect["dead_keys"])
  rows = [r for r in expect["rows"] if not r["node_only"]]
  hits = {(r["product"], r["version"], r["cve_id"]): _fires(db, r["product"], r["version"], r["cve_id"]) for r in rows}
  n_all = sum(hits.values())
  n_live = sum(v for k, v in hits.items() if k[0] not in dead)
  regress = json.loads((Path(golden) / "prototype_regressions.json").read_text())["rows"]
  fixed = {r["cve_id"] + "@" + r["product"]: _fires(db, r["product"], r["version"], r["cve_id"]) and
           db.execute("SELECT 1 FROM affected WHERE product=? AND cve_id=? AND source='curated'",
                      (r["product"], r["cve_id"])).fetchone() is not None for r in regress}
  misses = [list(k) for k, v in hits.items() if not v]
  ok = n_all >= expect["baseline_all"] and n_live >= expect["baseline_live"] and all(fixed.values())
  return {"ok": ok, "detail": {"all": f"{n_all}/{len(hits)}", "live": f"{n_live}/{sum(k[0] not in dead for k in hits)}",
                                "baseline": [expect["baseline_all"], expect["baseline_live"]], "misses": misses,
                                "regressions_fixed": f"{sum(fixed.values())}/{len(fixed)}"}}


def gate_t2(db):
  """The first-fixed version of every `<X` bound must not fire its own row."""
  bad = []
  for product, cons, cve in db.execute('SELECT product, "constraint", cve_id FROM affected'):
    for part in cons.split(","):
      m = re.match(r"^<(?!=)(.+)$", part)
      if m and (_parse_version(m.group(1), product) is None or _matches_constraint(m.group(1), cons, product)):
        bad.append([product, cve, cons])
  return {"ok": not bad, "detail": bad[:10]}


def _bump(product, rows):
  """A version above every bound of the product: first component of the highest bound plus one."""
  top = 0
  for cons in rows:
    for part in cons.split(","):
      key = _parse_version(re.sub(r"^[<>=]+", "", part), product)
      if key:
        top = max(top, key[0][0])
  return f"{top + 1}.0.0" if top < 1000 else f"{top + 1}"


def gate_t3(db, allow=None):
  """A version above the maximum bound of a product gives 0 findings. Open-ended curated rows need a reason."""
  bad = []
  for (product,) in db.execute("SELECT DISTINCT product FROM affected ORDER BY 1").fetchall():
    cons = [c for (c,) in db.execute('SELECT "constraint" FROM affected WHERE product=?', (product,))]
    v = _bump(product, cons)
    for cve, c in db.execute('SELECT cve_id, "constraint" FROM affected WHERE product=?', (product,)):
      if _matches_constraint(v, c, product) and not (allow or {}).get((product, cve)):
        bad.append([product, cve, c, v])
  return {"ok": not bad, "detail": bad[:10]}


def gate_t4(golden):
  cases = json.loads((Path(golden) / "matcher_cases.json").read_text())["cases"]
  bad = [c for c in cases if _matches_constraint(c["version"], c["constraint"], c["product"]) != c["expected"]]
  return {"ok": not bad, "detail": {"cases": len(cases), "failed": bad}}


LIMITS = {"delta_pct": 25, "delta_floor": 20, "max_bytes": 32 * 2**20}


def read_delta_overrides(path):
  """TSV `product<TAB>reason`: products exempt from the row-delta gate for a run with a known large change. The file is optional."""
  if not Path(path).exists():
    return {}
  out = {}
  for line in Path(path).read_text().splitlines():
    if line.strip() and not line.startswith("#"):
      product, reason = (line.split("\t") + ["", ""])[:2]
      if not product.strip() or not reason.strip():
        raise ValueError(f"delta override line without a product or reason: {line!r}")
      out[product.strip()] = reason.strip()
  return out


def gate_row_delta(old, new, pct, floor, exempt=None):
  """Per-product (product, CVE) pair counts within limits: a change of more than max(floor, pct % of old) fails.
  `old` and `new` are {product: count}; a product missing from `new` counts 0. A product absent from `old` is new in
  the product map and is exempt, as is a product in `exempt` ({product: reason}, from allowlist/delta.tsv)."""
  exempt = exempt or {}
  over = [[p, old[p], new.get(p, 0)] for p in sorted(old)
          if p not in exempt and abs(new.get(p, 0) - old[p]) > max(floor, old[p] * pct / 100)]
  return {"ok": not over, "detail": {"over": over, "pct": pct, "floor": floor, "exempt": sorted(p for p in exempt if p in old)}}


def gate_size(path, max_bytes):
  size = Path(path).stat().st_size
  return {"ok": size <= max_bytes, "detail": {"bytes": size, "max": max_bytes}}


def run_gates(db_path, root, golden=None, baseline=None, limits=None):
  """Run every gate on a built database. Returns {gate: {ok, detail}}; `ok` for all means the build passes.

  With a real `baseline` (the pairs of the previous build) the row-delta gate runs, and a lost pair whose CVE is
  now a REJECTED tombstone is excused. Without one the lost check uses the overlay pairs and excuses nothing."""
  limits = {**LIMITS, **(limits or {})}
  root = Path(root)
  golden = golden or root / "tests/golden"
  allow = read_allowlist(root / "allowlist/lost.tsv")
  db = connect(db_path)
  out = {"integrity": gate_integrity(db), "schema": gate_schema(db)}
  if out["schema"]["ok"]:
    out["t1_recall"] = gate_t1(db, golden)
    out["t2_first_fixed"] = gate_t2(db)
    out["t3_above_max"] = gate_t3(db, {(p, c): r for (p, c), r in allow.items() if r.startswith("open-ended")})
    out["t4_matcher"] = gate_t4(golden)
    now = pairs(db)
    lost = lost_pairs(baseline if baseline is not None else overlay_pairs(root), now, allow)
    tombstoned = 0
    if baseline is not None:
      rejected = {c for (c,) in db.execute("SELECT cve_id FROM vuln WHERE state='REJECTED'")}
      tombstoned = sum(c in rejected for _, c in lost["unlisted"])
      lost["unlisted"] = [pc for pc in lost["unlisted"] if pc[1] not in rejected]
      kept = {pc for pc in baseline if not (pc not in now and pc[1] in rejected)}  # tombstoned losses are not counted
      out["row_delta"] = gate_row_delta(Counter(p for p, _ in kept), Counter(p for p, _ in now), limits["delta_pct"], limits["delta_floor"],
                                        read_delta_overrides(root / "allowlist/delta.tsv"))
    out["lost_cves"] = {"ok": not lost["unlisted"], "detail": {"allowed": len(lost["allowed"]), "tombstoned": tombstoned,
                                                              "unlisted": lost["unlisted"][:10]}}
  db.close()
  out["size"] = gate_size(db_path, limits["max_bytes"])
  return out
