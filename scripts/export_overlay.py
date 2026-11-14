"""One-off export of the edge-node static catalog into overlay/curated.json.

usage: EDGE_NODE_PATH=<edge-node checkout> python3 scripts/export_overlay.py
Also writes tests/golden/matcher_cases.json (the UNIT table of tests/test_cve_matcher_versions.py)
and tests/golden/vulhub_expect.json (the EXPECT table of tests/test_cve_recall_offline.py).
redmesh-vulndb is the master of overlay/curated.json from the export on.
"""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EDGE = Path(os.environ["EDGE_NODE_PATH"])
RED_MESH = EDGE / "extensions/business/cybersec/red_mesh"
sys.path.insert(0, str(EDGE))

# Product keys no probe passes to check_cves (detection_inventory.PRODUCTS_WITHOUT_PROBE).
DEAD_KEYS = ["struts2", "spring_framework", "spring_cloud_function", "django", "laravel_ignition", "libvncserver"]


def literal(path, name):
  tree = ast.parse(path.read_text())
  for node in tree.body:
    if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == name:
      return ast.literal_eval(node.value)
  raise KeyError(name)


def main():
  from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, entry_applicability
  commit = subprocess.check_output(["git", "-C", str(EDGE), "rev-parse", "--short", "HEAD"], text=True).strip()
  rows = [
    {"product": e.product, "constraint": e.constraint, "cve_id": e.cve_id, "severity": e.severity.value,
     "title": e.title, "cwe": e.cwe_id, "client_side": int(entry_applicability(e) == "client")}
    for e in CVE_DATABASE
  ]
  rows.sort(key=lambda r: (r["product"], r["cve_id"], r["constraint"]))
  out = {"source_commit": commit, "row_count": len(rows), "rows": rows}
  (ROOT / "overlay/curated.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n")
  cases = [dict(zip(("product", "version", "constraint", "expected", "why"), c))
           for c in literal(RED_MESH / "tests/test_cve_matcher_versions.py", "UNIT")]
  (ROOT / "tests/golden/matcher_cases.json").write_text(
    json.dumps({"source_commit": commit, "cases": cases}, indent=1) + "\n")
  expect = [{"product": p, "version": v, "cve_id": c,
             "node_only": (p, v, c) == ("openssh", "8.9", "CVE-2024-6387")}
            for p, v, c in literal(RED_MESH / "tests/test_cve_recall_offline.py", "EXPECT")]
  (ROOT / "tests/golden/vulhub_expect.json").write_text(json.dumps(
    {"source_commit": commit, "dead_keys": DEAD_KEYS, "baseline_all": 31, "baseline_live": 24,
     "note": "node_only: the node suppresses it through the Ubuntu backport table, so the builder gate skips it",
     "rows": expect}, indent=1) + "\n")
  print(f"overlay rows={len(rows)} cases={len(cases)} expect={len(expect)} commit={commit}")


if __name__ == "__main__":
  main()
