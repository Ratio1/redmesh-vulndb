"""Cut a small fixture cache (well under 1 MB) out of a full fetch cache.

usage: python3 -I scripts/make_fixtures.py --src <full cache> --dst tests/fixtures/cache
The CVE list is the vulhub EXPECT table, the 9 prototype regressions and tests/fixtures/ids.txt.
Output is deterministic (fixed gzip and zip timestamps). Run `redmesh-vulndb fetch --manifest-only` is done here too.
"""
import argparse
import gzip
import io
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from redmesh_vulndb import fetch, nvd  # noqa: E402


def wanted_ids():
  ids = set()
  for name in ("vulhub_expect.json", "prototype_regressions.json"):
    ids |= {r["cve_id"] for r in json.loads((ROOT / "tests/golden" / name).read_text())["rows"]}
  for line in (ROOT / "tests/fixtures/ids.txt").read_text().splitlines():
    line = line.split("#")[0].strip()
    if line:
      ids.add(line)
  return ids


def gz_bytes(obj):
  buf = io.BytesIO()
  with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=9) as g:
    g.write(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode())
  return buf.getvalue()


def write_zip(path, files):
  with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name, data in sorted(files.items()):
      z.writestr(zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0)), data, zipfile.ZIP_DEFLATED, 9)


def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--src", required=True)
  ap.add_argument("--dst", required=True)
  a = ap.parse_args()
  src, dst = Path(a.src), Path(a.dst)
  ids = wanted_ids()
  found = fetch.inputs(src)
  for kind in ("nvd", "kev", "epss", "cvelist", "overrides"):
    (dst / kind).mkdir(parents=True, exist_ok=True)
  # NVD: keep the vulnerabilities of every feed that are in `ids`
  for path in found["nvd"]:
    keep = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
      for v in nvd.stream_vulns(f):
        if v["cve"]["id"] in ids:
          keep.append(v)
    out = dst / "nvd" / path.name
    if keep or "modified" in path.name:
      out.write_bytes(gz_bytes({"format": "NVD_CVE", "version": "2.0", "vulnerabilities": keep}))
      print(path.name, len(keep))
  # cvelist: records in `ids`
  files = {}
  with zipfile.ZipFile(found["cvelist"][-1]) as z:
    for name in z.namelist():
      if name.endswith(".json") and name.rsplit("/", 1)[-1][:-5] in ids:
        files[name] = z.read(name)
  write_zip(dst / "cvelist" / found["cvelist"][-1].name, files)
  print("cvelist", len(files))
  # overrides: files in `ids`
  files = {}
  with zipfile.ZipFile(found["overrides"][-1]) as z:
    for name in z.namelist():
      if "/data/" in name and name.rsplit("/", 1)[-1][:-5] in ids:
        files[name] = z.read(name)
  write_zip(dst / "overrides" / found["overrides"][-1].name, files)
  print("overrides", len(files))
  kev = json.loads(found["kev"][-1].read_text())
  kev["vulnerabilities"] = [v for v in kev["vulnerabilities"] if v["cveID"] in ids]
  kev["count"] = len(kev["vulnerabilities"])
  (dst / "kev/kev.json").write_text(json.dumps(kev, indent=0, sort_keys=True) + "\n")
  with gzip.open(found["epss"][-1], "rt", encoding="utf-8") as f:
    lines = f.read().splitlines()
  keep = [lines[0], lines[1]] + [ln for ln in lines[2:] if ln.split(",")[0] in ids]
  buf = io.BytesIO()
  with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as g:
    g.write(("\n".join(keep) + "\n").encode())
  (dst / "epss/epss_scores-current.csv.gz").write_bytes(buf.getvalue())
  src_manifest = json.loads((src / "manifest.json").read_text())
  fetch.write_manifest(dst, src_manifest.get("sources"))
  total = sum(p.stat().st_size for p in dst.rglob("*") if p.is_file())
  print("fixture bytes", total)


if __name__ == "__main__":
  main()
