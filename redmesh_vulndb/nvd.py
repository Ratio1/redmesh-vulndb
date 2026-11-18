"""NVD JSON 2.0 feeds and the anchore/nvd-data-overrides layer.

Ported from the 2026-11-13 prototype (`ingest_nvd.py`, `proto_build.py`). Streams each feed and keeps
only the CVEs that have a row for a mapped product (plus rejected ones, for tombstones).
"""
import gzip
import json
import re
import zipfile
from collections import Counter

from .versions import _LETTER_RELEASE_PRODUCTS

CISA_ADP = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
PRE = re.compile(r"^(alpha|beta|rc|pre|milestone|m|a|b|dev|preview|snapshot)\d*$", re.I)
DISTRO_REV = re.compile(r"^\d+(\.\d+)*[a-z]?-\d")  # 9.0.35-3.39.1, 2.2.15-60: package revision, not upstream
LETTER_RELEASE = _LETTER_RELEASE_PRODUCTS  # the vendored matcher's list: a letter on any other product is a pre-release
EXACT_OK = re.compile(r"^\d+(\.\d+)*[a-z]?$")  # plain release, optionally one letter (1.0.1f)
BANNER_OK = re.compile(r"^\d+(\.\d+)*-[SP]\d+$")  # BIND edition / patch level
MEMBER_LIMIT = 64 << 20  # bytes uncompressed, per zip member


def exact_ok(v):
  return bool(EXACT_OK.match(v) or BANNER_OK.match(v))


def read_member(z, info):
  """Bytes of a zip member, refusing one whose declared size is over MEMBER_LIMIT."""
  if info.file_size > MEMBER_LIMIT:
    raise ValueError(f"zip member too large: {info.filename} ({info.file_size} bytes)")
  return z.read(info)


def split_cpe(s):
  """Split a CPE 2.3 formatted string on unescaped ':'."""
  out, cur, esc = [], [], False
  for ch in s:
    if esc:
      cur.append(ch)
      esc = False
    elif ch == "\\":
      cur.append(ch)
      esc = True
    elif ch == ":":
      out.append("".join(cur))
      cur = []
    else:
      cur.append(ch)
  out.append("".join(cur))
  return out


def stream_vulns(fileobj, first=1 << 16, more=1 << 22):
  """Yield the items of the top-level 'vulnerabilities' array without loading the whole feed."""
  dec = json.JSONDecoder()
  f = fileobj
  buf = ""
  while '"vulnerabilities"' not in buf or "[" not in buf[buf.index('"vulnerabilities"'):]:
    chunk = f.read(first)
    if not chunk:
      return
    buf += chunk
  buf = buf[buf.index("[", buf.index('"vulnerabilities"')) + 1:]
  pos, eof = 0, False
  while True:
    n = len(buf)
    while pos < n and buf[pos] in " \t\r\n,":
      pos += 1
    if pos < n and buf[pos] == "]":
      return
    try:
      if pos >= n:
        raise json.JSONDecodeError("need more", buf, pos)
      obj, end = dec.raw_decode(buf, pos)
    except json.JSONDecodeError:
      if eof:
        raise
      chunk = f.read(more)
      eof = not chunk
      buf, pos = buf[pos:] + chunk, 0
      continue
    yield obj
    pos = end


def norm_ver(product, v):
  """Map an NVD or CNA version token to the RedMesh banner form. None means unusable."""
  if v is None:
    return None
  v = v.strip().lstrip("vV")
  if v in ("", "*", "-"):
    return None
  if product == "nginx" and v.lower().startswith("r"):
    return None  # NGINX Plus R-numbers
  if DISTRO_REV.match(v):
    return None
  if product == "openssh":
    v = re.sub(r"p\d+$", "", v)  # the probe feeds 8.9, not 8.9p1
  if not re.match(r"^\d", v) or "," in v or " " in v:
    return None
  return v


def row_constraint(prod, version, upd, vsi, vse, vei, vee, stats):
  """One cpeMatch to (constraint, kind) or None. Counts the reason a row is dropped."""
  parts = []
  for op, val in ((">=", vsi), (">", vse), ("<=", vei), ("<", vee)):
    if val:
      nv = norm_ver(prod, val)
      if nv is None:
        stats["nvd_bound_unusable"] += 1
        return None
      parts.append(op + nv)
  if parts:
    if not (vei or vee):
      stats["nvd_open_ended_dropped"] += 1  # a lower bound alone has no known fix: it would match every later release
      return None
    return ",".join(parts), "range"
  nv = norm_ver(prod, version)
  if nv is None:
    stats["nvd_star_only_row"] += 1  # open-ended "all versions"
    return None
  u = (upd or "").strip()
  if u and u not in ("*", "-"):
    if PRE.match(u) and not (prod in LETTER_RELEASE and re.match(r"^[a-z]$", u)):
      stats["nvd_exact_prerelease_skip"] += 1
      return None
    if (prod == "openssh" and re.match(r"^p\d+$", u)) or u.isdigit():
      pass  # openssh p-suffix dropped (banner form); jetty v-date stamps dropped
    elif prod == "bind" and re.match(r"^[sp]\d+$", u, re.I):
      nv = f"{nv}-{u[0].upper()}{u[1:]}"
    else:
      nv += u
  if not exact_ok(nv):
    stats["nvd_exact_odd_dropped"] += 1  # sp1, cp01, gamma, netsec, _rev1.15, 7.x-1.0, -gold, pre-release in the version
    return None
  return "==" + nv, "exact"


def config_rows(cfgs, vp2prod, stats):
  """Rows (product, constraint, kind, platform_dependent) for the mapped products in NVD configurations."""
  rows = []
  for cfg in cfgs or []:
    nodes = cfg.get("nodes", [])
    platform = any(nd.get("cpeMatch") and not any(cm.get("vulnerable") for cm in nd["cpeMatch"]) for nd in nodes)
    pdep = int((cfg.get("operator") or "").upper() == "AND" and platform)
    for node in nodes:
      for cm in node.get("cpeMatch", []):
        if not cm.get("vulnerable"):
          continue
        p = split_cpe(cm.get("criteria", ""))
        vendor, product = (p[3].replace("\\", ""), p[4].replace("\\", "")) if len(p) > 5 else ("", "")
        prod = vp2prod.get((vendor, product))
        if not prod:
          continue
        stats["nvd_rows"] += 1
        stats[f"hit {vendor}:{product}"] += 1
        if node.get("negate"):
          stats["nvd_negated_skip"] += 1
          continue
        got = row_constraint(prod, p[5], p[6] if len(p) > 6 else "", cm.get("versionStartIncluding"),
                             cm.get("versionStartExcluding"), cm.get("versionEndIncluding"),
                             cm.get("versionEndExcluding"), stats)
        if got:
          rows.append((prod, got[0], got[1], pdep))
  return rows


def metrics_of(c):
  out = []
  for key, items in (c.get("metrics") or {}).items():
    if not key.startswith("cvssMetric"):  # skip ssvcV203 and the like
      continue
    for m in items:
      d = m.get("cvssData", {})
      src = m.get("source")
      source = "nvd" if src == "nvd@nist.gov" else "adp" if src == CISA_ADP else "cna"
      if d.get("vectorString"):
        out.append((d.get("version"), d["vectorString"], d.get("baseScore"), source))
  return out


def parse_cve(c, vp2prod, overrides, stats):
  """Normalised record for one NVD vulnerability, or None when it has no mapped row and is not rejected."""
  cid = c["id"]
  rejected = c.get("vulnStatus") == "Rejected"
  cfgs = c.get("configurations")
  if cfgs:
    rows = config_rows(cfgs, vp2prod, stats)
    layer = "nvd"
  else:
    rows = (overrides.get(cid) or {}).get("rows", [])  # not yet analysed by NVD: layer the override on top
    layer = "override"
  if not rows and not rejected:
    return None
  desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
  cwes = [d["value"] for w in c.get("weaknesses", []) for d in w.get("description", []) if d["value"].startswith("CWE-")]
  return {"rejected": rejected, "published": c.get("published"), "description": desc,
          "cwe": cwes[0] if cwes else "", "cvss": metrics_of(c), "rows": rows, "layer": layer}


def load_overrides(path, vp2prod, stats):
  """cve_id to {rows, description, published} from the anchore/nvd-data-overrides zip (CVEs with a mapped row only)."""
  out = {}
  with zipfile.ZipFile(path) as z:
    for name in sorted(z.namelist()):
      if "/data/" not in name or not name.endswith(".json"):
        continue
      d = json.loads(read_member(z, z.getinfo(name)))
      cid = (d.get("_annotation") or {}).get("cve_id") or name.rsplit("/", 1)[1][:-5]
      rows = config_rows((d.get("cve") or {}).get("configurations"), vp2prod, Counter())
      if rows:
        out[cid] = {"rows": rows, "description": (d.get("_annotation") or {}).get("description", ""),
                    "published": (d.get("_annotation") or {}).get("published")}
  stats["override_cves"] = len(out)
  return out


def ingest(paths, vp2prod, overrides, stats):
  """Feeds in order (yearly, then modified): later feeds replace earlier records. Returns {cve_id: record}."""
  recs, seen, total = {}, set(), 0
  for path in paths:
    n = 0
    with gzip.open(path, "rt", encoding="utf-8") as f:
      for v in stream_vulns(f):
        rec = parse_cve(v["cve"], vp2prod, overrides, stats)
        seen.add(v["cve"]["id"])
        if rec:
          recs[v["cve"]["id"]] = rec
        else:
          recs.pop(v["cve"]["id"], None)
        n += 1
    stats[f"feed {path.name}"] = n
    total += n
  if not total:
    raise ValueError("NVD feeds hold 0 vulnerabilities")
  for cid, ov in overrides.items():  # CVEs the feeds do not carry at all yet
    if cid not in seen:
      recs[cid] = {"rejected": False, "published": ov["published"], "description": ov["description"],
                   "cwe": "", "cvss": [], "rows": ov["rows"], "layer": "override"}
  return recs
