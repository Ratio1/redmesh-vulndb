"""Build the vulndb SQLite file from the fetch cache (offline), deterministically.

Rules (RM-169 spec): NVD rows (with the anchore overrides layered on CVEs NVD has not analysed) for the
mapped products; CNA ranges only for (product, CVE) pairs NVD has no row for; the curated overlay wins per
pair; rejected CVEs become tombstones. The writer inserts in primary-key order into a fixed page size and
runs VACUUM INTO, so the same inputs give the same file. `content_hash` covers a canonical row dump.
"""
import csv
import datetime
import gzip
import hashlib
import json
import re
import sqlite3
import tomllib
from collections import Counter
from pathlib import Path

from . import __version__, cvelist, distro, fetch, nvd
from .versions import MATCHER_REV, validate_constraint

_PKG = Path(__file__).resolve().parents[1]
ROOT = _PKG if (_PKG / "product_map.toml").exists() else Path.cwd()  # data files: next to the package, else the working directory
MODEL, REVISION, ADDITION = 1, 0, 1  # 1.0.1: distro_fix table added
SCHEMA_VERSION = f"{MODEL}.{REVISION}.{ADDITION}"
PAGE_SIZE = 4096
DDL = """
CREATE TABLE vuln(cve_id TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('PUBLISHED','REJECTED')),
  published TEXT, title TEXT NOT NULL, cwe TEXT, kev INTEGER NOT NULL, kev_date_added TEXT,
  epss REAL, epss_percentile REAL, display_cvss_version TEXT, display_cvss_score REAL,
  display_cvss_source TEXT,
  severity TEXT NOT NULL CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN'))) WITHOUT ROWID;
CREATE TABLE affected(product TEXT NOT NULL, "constraint" TEXT NOT NULL, cve_id TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('nvd','cna','curated')),
  confidence TEXT NOT NULL CHECK(confidence IN ('certain','firm','tentative')), reason TEXT NOT NULL,
  platform_dependent INTEGER NOT NULL, client_side INTEGER NOT NULL,
  PRIMARY KEY(product, cve_id, "constraint")) WITHOUT ROWID;
CREATE TABLE cvss(cve_id TEXT NOT NULL, version TEXT NOT NULL, vector TEXT NOT NULL, score REAL,
  source TEXT NOT NULL CHECK(source IN ('cna','nvd','adp')), PRIMARY KEY(cve_id, version, source, vector)) WITHOUT ROWID;
CREATE TABLE meta(k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE eol(product TEXT PRIMARY KEY, oldest_supported TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE distro_fix(distro TEXT NOT NULL CHECK(distro IN ('ubuntu','debian')), release TEXT NOT NULL,
  product TEXT NOT NULL, package TEXT NOT NULL, cve_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('fixed','not_affected','open')), fixed_version TEXT, source TEXT NOT NULL,
  PRIMARY KEY(distro, release, package, cve_id)) WITHOUT ROWID;
"""
# Display CVSS, first match wins: v3.x keeps the label (v4 display is RM-170), so CNA v3, then NVD v3, then CISA ADP v3,
# then v4 (CNA, NVD, ADP), then v2.
DISPLAY_ORDER = [("3.1", "cna"), ("3.0", "cna"), ("3.1", "nvd"), ("3.0", "nvd"), ("3.1", "adp"), ("3.0", "adp"),
                 ("4.0", "cna"), ("4.0", "nvd"), ("4.0", "adp"), ("2.0", "nvd"), ("2.0", "cna")]


CWE = re.compile(r"CWE-\d+")
VECTOR = re.compile(r"[A-Za-z]{1,3}:[A-Za-z]{1,6}(/[A-Za-z]{1,3}:[A-Za-z]{1,6})*")  # v4 U:Clear|Green|Amber|Red
DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


_NON_UNIX_PLATFORM = re.compile(r"\b(?:on|for)\s+(?:unpatched\s+)?(?:Microsoft\s+)?(?:Windows|Win32|WinNT|OS/?2|NetWare|Cygwin)\b", re.I)

def band(score):
  """Severity band of a CVSS score; UNKNOWN without one."""
  return "UNKNOWN" if score is None else "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW" if score > 0 else "INFO"


def keep_cvss(ver, vec, score, stats):
  """Shape check of a feed CVSS entry: `CVSS:3.x/` or `CVSS:4.0/` prefix (none for 2.0), metric grammar, score 0-10."""
  body = vec[len(f"CVSS:{ver}/"):] if vec.startswith(f"CVSS:{ver}/") else vec if ver == "2.0" else ""
  ok = len(vec) <= 200 and bool(VECTOR.fullmatch(body)) and (score is None or isinstance(score, (int, float)) and 0 <= score <= 10)
  stats["cvss_invalid_dropped"] += not ok
  return ok


def clean_str(s, pattern, stats, what):
  """`s` when it fully matches `pattern` (and is a real date for DATE), else None and a count."""
  if s and not (pattern.fullmatch(s) and (pattern is not DATE or _real_date(s))):
    stats[f"{what}_invalid"] += 1
    return None
  return s or None


def _real_date(s):
  try:
    datetime.date.fromisoformat(s)
    return True
  except ValueError:
    return False


def sha256_bytes(b):
  return hashlib.sha256(b).hexdigest()


def load_config(root):
  """Product map, overlay and eol table from the repository data files."""
  root = Path(root)
  pmap = tomllib.loads((root / "product_map.toml").read_text())
  pm = pmap["products"]
  vp2prod, aliases = {}, {}
  for prod, spec in pm.items():
    for name in spec.get("nvd", []):
      vendor, product = name.split(":", 1)
      vp2prod[(vendor, product)] = prod
      aliases[(vendor.lower(), product.lower())] = prod
    for vendor, product in spec.get("cna", []):
      aliases[(vendor.lower(), product.lower())] = prod
  overlay = json.loads((root / "overlay/curated.json").read_text())
  eol = {k: v["oldest_supported"] for k, v in tomllib.loads((root / "eol.toml").read_text()).items()}
  dm_path = root / "distro_map.toml"
  dm = tomllib.loads(dm_path.read_text()) if dm_path.exists() else None  # optional: without it no distro_fix rows
  files = {n: sha256_bytes((root / n).read_bytes()) for n in ("product_map.toml", "overlay/curated.json", "eol.toml", *(["distro_map.toml"] if dm else []))}
  rules = {"component_products": frozenset(pmap.get("rules", {}).get("component_products", []))}
  supersede = {tuple(p) for p in pmap.get("supersede", {}).get("pairs", [])}
  return {"products": pm, "rules": rules, "supersede": supersede, "vp2prod": vp2prod, "aliases": aliases, "overlay": overlay, "eol": eol, "files": files, "distro": dm}


def load_kev(path):
  d = json.loads(Path(path).read_text())
  return {v["cveID"]: v.get("dateAdded") for v in d["vulnerabilities"]}, d.get("catalogVersion", "")


def load_epss(path, wanted):
  scores, model = {}, {}
  with gzip.open(path, "rt", encoding="utf-8") as f:
    first = f.readline()
    if first.startswith("#"):
      model = dict(kv.split(":", 1) for kv in first.strip().lstrip("#").split(","))
    else:
      f.seek(0)
    for row in csv.DictReader(f):
      if row["cve"] in wanted:
        scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
  return scores, model


def display_cvss(rows):
  for ver, src in DISPLAY_ORDER:
    for v, vec, score, s in rows:
      if (v, s) == (ver, src) and score is not None:
        return ver, score, src
  return None, None, None


def drop_component_rows(affected, curated, kev, component_products, stats):
  """Component-CVE rule: a CVE with an NVD row for a component product (openssl) loses its NVD rows for other products.

  A server banner does not tell which OpenSSL the product bundles. Kept: curated pairs and KEV CVEs.
  Returns the dropped (product, cve) pairs: the lost-CVE gate excuses them."""
  dropped = set()
  comp_cves = {k[1] for k, row in affected.items() if row[0] == "nvd" and k[0] in component_products}
  for key in [k for k, row in affected.items() if row[0] == "nvd" and k[1] in comp_cves and k[0] not in component_products
              and (k[0], k[1]) not in curated and k[1] not in kev]:
    del affected[key]
    dropped.add((key[0], key[1]))
    stats["component_cve_dropped"] += 1
  return dropped


def superseded_pairs(supersede, affected):
  """The supersede pairs the feed covers with at least one range (non-`==`) row; the others keep their curated rows."""
  return {(k[0], k[1]) for k in affected if (k[0], k[1]) in supersede and not k[2].startswith("==")}


def assemble(cfg, cache, stats, baseline_cves=frozenset()):
  """Run the ingest and apply the build rules. Returns (tables, extra meta).

  `baseline_cves`: every CVE id of the previous build. One that a feed now rejects becomes a tombstone even
  with no rows left, so it stays visible as REJECTED instead of silently vanishing."""
  manifest = fetch.verify(cache)
  inp = fetch.inputs(cache, fetch.selected(cache, manifest), fetch.has_elts(manifest))  # exactly the files the manifest names
  vp2prod = cfg["vp2prod"]
  overrides = nvd.load_overrides(inp["overrides"][-1], vp2prod, stats) if inp["overrides"] else {}
  nrecs = nvd.ingest(inp["nvd"], vp2prod, overrides, stats)
  overlay_rows = cfg["overlay"]["rows"]
  kev, kev_version = load_kev(inp["kev"][-1])
  wanted = set(nrecs) | {r["cve_id"] for r in overlay_rows} | set(baseline_cves)
  crecs = cvelist.ingest(inp["cvelist"][-1], cfg["aliases"], wanted, stats)

  affected = {}  # (product, cve, constraint) -> [source, confidence, reason, platform_dependent, client_side]

  def add(prod, cve, cons, source, conf, reason, pdep=0, client=0):
    if not validate_constraint(cons, prod):
      stats["row_invalid_dropped"] += 1
      return
    cur = affected.setdefault((prod, cve, cons), [source, conf, reason, pdep, client])
    cur[3] = min(cur[3], pdep)

  nvd_pairs = set()
  for cve, r in nrecs.items():
    # NVD gives old Apache CVEs no platform node; their description names the platform. An upstream-build
    # banner makes Apache rows firm (edge RM-204), so a Windows/OS2/NetWare/Cygwin-only row must stay tentative.
    windows_only = bool(_NON_UNIX_PLATFORM.search(r.get("description") or ""))
    for prod, cons, kind, pdep in r["rows"]:
      pdep = 1 if prod == "apache" and windows_only else pdep
      nvd_pairs.add((prod, cve))
      reason = "nvd_override" if r["layer"] == "override" else "nvd_range" if kind == "range" else "nvd_exact"
      add(prod, cve, cons, "nvd", "firm" if kind == "range" else "tentative", reason, pdep)  # override rows: NVD source, same CPE format
      stats[f"rows_from_{r['layer']}"] += 1
  for cve, r in crecs.items():
    for prod, cons, quality in r["cna_rows"]:
      if (prod, cve) in nvd_pairs:
        stats["cna_row_has_nvd"] += 1
      elif quality == "low" and cve not in kev:
        stats["cna_low_dropped"] += 1
      else:
        add(prod, cve, cons, "cna", "tentative", "cna_range")
  curated = {(r["product"], r["cve_id"]) for r in overlay_rows}
  # The component rule runs before supersede (no supersede pair is an OpenSSL CVE today), so a dropped pair never supersedes.
  component_dropped = drop_component_rows(affected, curated, kev, cfg["rules"]["component_products"], stats)
  stats["component_dropped_pairs"] = sorted([p, c] for p, c in component_dropped)
  superseded = superseded_pairs(cfg["supersede"], affected)  # partial curated rows: the feed's ranges win when it has a range row
  stats["curated_superseded"] = len(superseded)
  for key in [k for k in affected if (k[0], k[1]) in curated - superseded]:
    del affected[key]
  for r in overlay_rows:
    if (r["product"], r["cve_id"]) in superseded:
      continue
    add(r["product"], r["cve_id"], r["constraint"], "curated", "firm", "curated", r.get("platform_dependent", 0), r["client_side"])
  client_cves = {r["cve_id"] for r in overlay_rows if r["client_side"]}
  for (prod, cve, cons), row in affected.items():
    if cve in client_cves:
      row[4] = 1

  rejected = {c for c, r in nrecs.items() if r["rejected"]} | {c for c, r in crecs.items() if r["state"] == "REJECTED"}
  with_rows = {k[1] for k in affected}
  tombstones = rejected & (with_rows | set(baseline_cves))
  for key in [k for k in affected if k[1] in tombstones]:
    del affected[key]
  stats["tombstones"] = len(tombstones)

  cves = sorted({k[1] for k in affected} | tombstones)
  epss, epss_model = load_epss(inp["epss"][-1], set(cves))
  overlay_by_cve = {}
  for r in sorted(overlay_rows, key=lambda r: (r["cve_id"], r["product"], r["constraint"])):
    overlay_by_cve.setdefault(r["cve_id"], r)
  vuln, cvss = [], set()
  for cve in cves:
    n, c, o = nrecs.get(cve), crecs.get(cve), overlay_by_cve.get(cve)
    published = clean_str(((c or {}).get("published") or (n or {}).get("published") or "")[:10], DATE, stats, "published")
    desc = re.split(r"(?<=[.!?])\s", ((n or {}).get("description") or "").strip(), maxsplit=1)[0][:120]
    title = re.sub(r"[\x00-\x1f\x7f-\x9f]+", " ", (c or {}).get("title") or desc or (o or {}).get("title", "")).strip()
    cwe = clean_str((c or {}).get("cwe") or (n or {}).get("cwe") or (o or {}).get("cwe", ""), CWE, stats, "cwe")
    rows = {}
    for ver, vec, score, src in (c or {}).get("cvss", []):
      if keep_cvss(ver, vec, score, stats):
        rows.setdefault((ver, src, vec), score)
    cna_have = any(k[1] == "cna" for k in rows)
    for ver, vec, score, src in (n or {}).get("cvss", []):
      if (src != "cna" or not cna_have) and keep_cvss(ver, vec, score, stats):
        rows.setdefault((ver, src, vec), score)
    cvss |= {(cve, ver, vec, score, src) for (ver, src, vec), score in rows.items()}
    dv, ds, dsrc = display_cvss([(ver, vec, score, src) for (ver, src, vec), score in rows.items()])
    e = epss.get(cve, (None, None))
    vuln.append((cve, "REJECTED" if cve in tombstones else "PUBLISHED", published, title, cwe,
                 int(cve in kev), clean_str(kev.get(cve), DATE, stats, "kev_date_added"), e[0], e[1], dv, ds, dsrc,
                 (o or {}).get("severity") or band(ds)))
  tables = {
    "vuln": vuln,
    "affected": [(p, cons, cve, *row) for (p, cve, cons), row in affected.items()],
    "cvss": sorted(cvss, key=lambda r: (r[0], r[1], r[4], r[2])),
    "eol": sorted(cfg["eol"].items()),
  }
  stats["pairs"] = len({(r[0], r[2]) for r in tables["affected"]})
  fix_rows = distro.distro_fix_rows(cfg, inp, {(r[0], r[2]) for r in tables["affected"]}, stats)
  if fix_rows is not None:
    tables["distro_fix"] = fix_rows
  stats["zero_hit_names"] = sorted(n for spec in cfg["products"].values() for n in spec.get("nvd", [])
                                   if not stats.get(f"hit {n}"))
  nvd_ids = sha256_bytes("".join(f"{k}:{manifest['inputs'][k]['sha256']}\n" for k in sorted(manifest["inputs"])
                                 if k.startswith("nvd/")).encode())[:16]
  src = manifest.get("sources", {})
  ov_commit = src.get("overrides", {}).get("commit") or (inp["overrides"][-1].stem.rsplit("-", 1)[-1] if inp["overrides"] else "none")
  snapshot = {
    "snapshot_nvd": nvd_ids,
    "snapshot_cvelist": src.get("cvelist", {}).get("release") or manifest["inputs"][str(inp["cvelist"][-1].relative_to(cache))]["sha256"][:16],
    "snapshot_nvd_overrides": ov_commit,
    "snapshot_kev": kev_version,
    "snapshot_epss": epss_model.get("score_date", ""),
    "epss_model_version": epss_model.get("model_version", ""),
    "overlay_source_commit": cfg["overlay"]["source_commit"],
    "overlay_row_count": str(cfg["overlay"]["row_count"]),
  }
  for kind in ("oval", "debian", "elts"):  # a distro source has no release tag: its snapshot is a hash of its input hashes
    if inp[kind] and "distro_fix" in tables:
      snapshot[f"snapshot_{kind}"] = sha256_bytes("".join(f"{k}:{manifest['inputs'][k]['sha256']}\n" for k in sorted(manifest["inputs"])
                                                         if k.startswith(kind + "/")).encode())[:16]
  build_id = "vulndb-" + sha256_bytes(json.dumps(
    [__version__, SCHEMA_VERSION, MATCHER_REV, snapshot, cfg["files"], {k: v["sha256"] for k, v in manifest["inputs"].items()},
     sorted(tombstones)],
    sort_keys=True).encode())[:12]
  meta = {"schema": SCHEMA_VERSION, "build_id": build_id, "matcher_rev": MATCHER_REV, **snapshot}
  tables["meta"] = sorted(meta.items())
  return tables, manifest


def write_db(path, tables):
  """Deterministic writer: fixed page size, rows inserted in primary-key order, VACUUM INTO, no timestamp."""
  db = sqlite3.connect(":memory:")
  db.execute(f"PRAGMA page_size={PAGE_SIZE}")
  db.executescript(DDL)
  for name, rows in tables.items():
    if rows:
      db.executemany(f"INSERT INTO {name} VALUES ({','.join('?' * len(rows[0]))})", sorted(rows, key=_pk(name)))
  db.execute(f"PRAGMA user_version={MODEL}")
  db.commit()
  path = Path(path)
  path.parent.mkdir(parents=True, exist_ok=True)
  path.unlink(missing_ok=True)
  db.execute("VACUUM INTO ?", (str(path),))
  db.close()


def _pk(table):
  return {"vuln": lambda r: r[0], "affected": lambda r: (r[0], r[2], r[1]), "cvss": lambda r: (r[0], r[1], r[4], r[2]),
          "meta": lambda r: r[0], "eol": lambda r: r[0], "distro_fix": lambda r: (r[0], r[1], r[3], r[4])}[table]


def content_hash(path):
  """sha256 over a canonical dump of every table's rows (sorted), not over file bytes."""
  db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
  h = hashlib.sha256()
  h.update(f"user_version={db.execute('PRAGMA user_version').fetchone()[0]}\n".encode())
  for name, ddl in db.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name").fetchall():
    cols = [c[1] for c in db.execute(f"PRAGMA table_info({name})")]
    h.update(f"table {name} {','.join(cols)}\n{ddl}\n".encode())
    order = ",".join(f'"{c}"' for c in cols)
    for row in db.execute(f"SELECT * FROM {name} ORDER BY {order}"):
      h.update((json.dumps(row, separators=(",", ":"), ensure_ascii=True) + "\n").encode())
  db.close()
  return h.hexdigest()


def build(cache, out, root=ROOT, log=print, baseline_cves=frozenset()):
  """Build `out` from `cache`. Returns the build record (also written to `<out>.build.json` by the CLI)."""
  stats = Counter()
  cfg = load_config(root)
  tables, manifest = assemble(cfg, cache, stats, baseline_cves)
  write_db(out, tables)
  out = Path(out)
  record = {
    "build_id": dict(tables["meta"])["build_id"], "schema": SCHEMA_VERSION, "content_hash": content_hash(out),
    "sha256": fetch.sha256_file(out), "bytes": out.stat().st_size,
    "counts": {k: len(v) for k, v in tables.items()},
    "inputs": {k: v["sha256"] for k, v in manifest["inputs"].items()},
    "stats": {k: v for k, v in sorted(stats.items(), key=lambda kv: str(kv[0])) if not k.startswith(("hit ", "feed "))},
    "hits": {k[4:]: v for k, v in sorted(stats.items()) if k.startswith("hit ")},
  }
  log(f"built {out} {record['bytes']} bytes content_hash={record['content_hash'][:16]} counts={record['counts']}")
  return record
