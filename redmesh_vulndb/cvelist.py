"""cvelistV5 release zip: CNA ranges for mapped products, CNA/ADP CVSS, titles.

Ported from the prototype (`cvelist_build.py`, the classifier of `cvelist_classify.py`, the CNA part of
`proto_build.py`). A CNA record reaches a product only through an exact case-folded (vendor, product)
alias pair of the product map. Open-ended ranges are dropped (`changes[]` parsing is deferred).
"""
import contextlib
import json
import re
import tempfile
import zipfile

from .nvd import exact_ok, norm_ver, read_member

INNER_LIMIT = 4 << 30  # bytes uncompressed; the real cves.zip is about 0.5 GB

NA = {"", "n/a", "na", "*", "unspecified", "unknown", "all", "all versions", "-", "none", "0", "x", "latest",
      "n.a.", "various"}
VL = re.compile(r"^[vV]?\d[0-9A-Za-z._\-+~:]*$")
HASH = re.compile(r"^[0-9a-f]{12,40}$")
EXPR = re.compile(r"^\s*(?:[<>]=?|=)\s*[vV]?\d[0-9A-Za-z._\-+~]*(?:\s*,\s*(?:[<>]=?|=)\s*[vV]?\d[0-9A-Za-z._\-+~]*)*\s*$")
V = r"[vV]?\d[0-9A-Za-z._\-+]*"
VERTOK = re.compile(r"\d+(?:\.\d+)+[a-z]?\d*", re.I)
EXPR_PART = re.compile(r"^\s*(>=|<=|>|<|=)\s*(" + V + r")\s*$")
CVSS_KEYS = {"cvssV4_0": "4.0", "cvssV3_1": "3.1", "cvssV3_0": "3.0", "cvssV2_0": "2.0"}


def vlike(x):
  return x is not None and len(x) <= 40 and bool(VL.match(x.strip())) and not HASH.match(x.strip())


def classify(version, lt, lte, vtype, status, dstatus):
  if status == "unaffected" and dstatus == "affected" and vlike(version):
    return "inverse"
  if status not in (None, "affected"):
    return "skip"
  if version and EXPR.match(version):
    return "expr"
  v = (version or "").strip()
  if (vtype or "").lower() in ("git", "original_commit_for_fix") or HASH.match(v):
    return "git"
  bound = lt if lt is not None else lte
  if bound is not None:
    b = bound.strip()
    if vlike(b):
      return "range"
    return "range_open" if b == "*" and vlike(v) else "freetext"
  if version is None or v.lower() in NA:
    return "na"
  return "exact" if vlike(v) else "freetext"


def branch_floor(v):
  m = re.match(r"^(\d+)\.(\d+)", v)
  return f"{m.group(1)}.{m.group(2)}" if m else None


def parse_freetext(text):
  """Regex pack from report 7 plus vendor patterns. Returns constraint strings."""
  t = (text or "").strip()
  if not t:
    return []
  m = re.search(r"Affected\s+([0-9a-z.,\s]+)\)", t, re.I)  # OpenSSL "Fixed in 3.0.3 (Affected 3.0.0,3.0.1)"
  if m:
    return ["==" + x.strip() for x in m.group(1).split(",") if VERTOK.fullmatch(x.strip())]
  m = re.search(rf"({V})\s+through\s+(?:versions\s+)?before\s+({V})", t, re.I)  # BIND
  if m:
    return [f">={m.group(1)},<{m.group(2)}"]
  m = re.match(rf"^\s*({V})\s+and\s+(?:prior|earlier|before|below|lower)", t, re.I)  # Oracle
  if m:
    b = branch_floor(m.group(1))
    return [f">={b},<={m.group(1)}" if b else f"<={m.group(1)}"]
  m = re.search(rf"(?:^|\s)({V})\s*(?:to|through|-|–|~)\s*({V})\s*$", t, re.I)
  if m:
    return [f">={m.group(1)},<={m.group(2)}"]
  m = re.search(rf"<=\s*({V})", t)
  if m:
    return ["<=" + m.group(1)]
  m = re.search(r"(?:prior to|before|earlier than|older than|<)\s*(.*)$", t, re.I)  # Samba multi-branch
  if m:
    toks = VERTOK.findall(m.group(1))
    if len(toks) == 1:
      return ["<" + toks[0]]
    return [f">={branch_floor(x)},<{x}" for x in toks if branch_floor(x)]
  return []


def cna_constraints(prod, cls, version, lt, lte):
  """(constraints, quality) for one CNA version entry. quality is 'medium' or 'low'; 'INVERSE' defers to the caller."""
  v = (version or "").strip()
  if cls == "range":
    out = []
    sv = norm_ver(prod, v)
    if sv and not re.match(r"^0(\.0)*$", sv):
      out.append(">=" + sv)
    b = norm_ver(prod, lt if lt is not None else lte)
    if not b:
      return [], None
    out.append(("<" if lt is not None else "<=") + b)
    return [",".join(out)], "medium"
  if cls == "expr":
    parts = []
    for p in v.split(","):
      m = EXPR_PART.match(p)
      val = norm_ver(prod, m.group(2)) if m else None
      if not val:
        return [], None
      if m.group(1) == "=" and not exact_ok(val):
        return [], None  # odd or pre-release exact version, same rule as NVD exact rows
      parts.append(("==" if m.group(1) == "=" else m.group(1)) + val)
    if not any(p.lstrip()[0] in "<=" for p in v.split(",")):
      return [], None  # no upper bound: open-ended, dropped
    return [",".join(parts)], "medium"
  if cls == "inverse":
    return "INVERSE", "low"
  if cls == "exact":
    m = re.fullmatch(r"(\d+(?:\.\d+)+)\s*-\s*(\d+(?:\.\d+)+)", v)  # "4.0.0-5.4.5"
    if m:
      return [f">={m.group(1)},<={m.group(2)}"], "low"
    sv = norm_ver(prod, v)
    return ([f"=={sv}"], "low") if sv and exact_ok(sv) else ([], None)
  if cls == "freetext":
    cs = parse_freetext(v if lt is None and lte is None else f"{v} to {lt or lte}")
    cs = [c for c in cs if all(norm_ver(prod, re.sub(r"^[<>=]+", "", x)) for x in c.split(","))]
    return (cs, "low") if cs else ([], None)
  return [], None  # range_open, git, na, skip: dropped


def cna_rows_of(cna, aliases, stats):
  """[(product, constraint, quality)] for the mapped (vendor, product) pairs of a CNA container."""
  rows, inverse = [], {}
  for a in cna.get("affected") or []:
    prod = aliases.get(((a.get("vendor") or "").strip().lower(), (a.get("product") or "").strip().lower()))
    for c in a.get("cpes") or []:
      parts = str(c).split(":")
      prod = prod or (aliases.get((parts[3].lower().replace("\\", ""), parts[4].lower().replace("\\", ""))) if len(parts) > 4 else None)
    if not prod:
      continue
    for v in a.get("versions") or []:
      cls = classify(v.get("version"), v.get("lessThan"), v.get("lessThanOrEqual"), v.get("versionType"),
                     v.get("status"), a.get("defaultStatus"))
      cs, quality = cna_constraints(prod, cls, v.get("version"), v.get("lessThan"), v.get("lessThanOrEqual"))
      if cs == "INVERSE":  # Red Hat style: unaffected fix versions
        fix = norm_ver(prod, v.get("version"))
        if fix:
          inverse.setdefault(prod, []).append(fix)
        continue
      stats[f"cna_{cls}_{'ok' if cs else 'drop'}"] += 1
      rows += [(prod, c, quality) for c in cs]
  for prod, fixes in inverse.items():
    if len(fixes) == 1:
      rows.append((prod, "<" + fixes[0], "low"))
    else:
      rows += [(prod, f">={branch_floor(f)},<{f}", "low") for f in fixes if branch_floor(f)]
  return rows


def metrics_of(container, source):
  out = []
  for m in container.get("metrics") or []:
    for k, ver in CVSS_KEYS.items():
      x = m.get(k)
      if isinstance(x, dict) and x.get("vectorString"):
        out.append((ver, x["vectorString"], x.get("baseScore"), source))
  return out


def title_of(cna):
  if cna.get("title"):
    return cna["title"].strip()[:120]
  desc = next((d.get("value", "") for d in cna.get("descriptions") or [] if d.get("lang", "en").startswith("en")), "")
  return re.split(r"(?<=[.!?])\s", desc.strip(), maxsplit=1)[0][:120]


def parse_record(d, aliases, stats):
  md = d.get("cveMetadata", {})
  cont = d.get("containers", {})
  cna = cont.get("cna") or {}
  cwes = [x["cweId"] for pt in cna.get("problemTypes") or [] for x in pt.get("descriptions") or [] if x.get("cweId")]
  metrics = metrics_of(cna, "cna")
  for adp in cont.get("adp") or []:
    metrics += metrics_of(adp, "adp")
    cwes = cwes or [x["cweId"] for pt in adp.get("problemTypes") or [] for x in pt.get("descriptions") or [] if x.get("cweId")]
  return {"state": md.get("state"), "published": md.get("datePublished"), "title": title_of(cna),
          "cwe": cwes[0] if cwes else "", "cvss": metrics, "cna_rows": cna_rows_of(cna, aliases, stats)}


@contextlib.contextmanager
def open_release(path):
  """The release zip. The live asset `<date>_all_CVEs_at_midnight.zip.zip` wraps `cves.zip`: copy it to disk, not memory."""
  with zipfile.ZipFile(path) as outer:
    inner = [i for i in outer.infolist() if i.filename.endswith(".zip")]
    if not inner:
      yield outer
      return
    if inner[0].file_size > INNER_LIMIT:
      raise ValueError(f"{inner[0].filename}: {inner[0].file_size} bytes uncompressed, over {INNER_LIMIT}")
    with outer.open(inner[0]) as src, tempfile.TemporaryFile() as tmp:
      n = 0
      while chunk := src.read(1 << 20):
        n += len(chunk)
        if n > INNER_LIMIT:
          raise ValueError(f"{inner[0].filename}: over {INNER_LIMIT} bytes uncompressed")
        tmp.write(chunk)
      with zipfile.ZipFile(tmp) as z:
        yield z


def ingest(path, aliases, wanted, stats):
  """{cve_id: record} for CVEs in `wanted` and for CVEs with a CNA row on a mapped product."""
  out, n = {}, 0
  with open_release(path) as z:
    for info in z.infolist():
      name = info.filename
      if not name.endswith(".json") or "/CVE-" not in name:
        continue
      d = json.loads(read_member(z, info))
      cid = d.get("cveMetadata", {}).get("cveId")
      rec = parse_record(d, aliases, stats)
      if cid in wanted or rec["cna_rows"]:
        out[cid] = rec
      n += 1
  if not n:
    raise ValueError(f"cvelist release {path} holds 0 records")
  stats["cvelist_records"] = n
  return out
