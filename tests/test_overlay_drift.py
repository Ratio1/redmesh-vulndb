"""The static edge-node CVE_DATABASE equals overlay/curated.json. Needs EDGE_NODE_PATH (an edge-node checkout)."""
import ast
import json
import os
from pathlib import Path

import pytest

from .conftest import ROOT

EDGE = os.environ.get("EDGE_NODE_PATH")
pytestmark = pytest.mark.skipif(not EDGE, reason="EDGE_NODE_PATH not set")
FIELDS = ("product", "constraint", "cve_id", "severity", "title", "cwe", "client_side")


def _module_assigns(path):
  for node in ast.parse(path.read_text()).body:
    target = node.target if isinstance(node, ast.AnnAssign) else node.targets[0] if isinstance(node, ast.Assign) else None
    if isinstance(target, ast.Name):
      yield target.id, node.value


def _static_rows():
  """CVE_DATABASE read from the edge-node sources: CveEntry calls, EXPANDED_CVE_ROWS tuples, client-side flags.

  Read with `ast`: importing cve_db.py needs edge-node's dependencies."""
  base = Path(EDGE) / "extensions/business/cybersec/red_mesh"
  client, rows = set(), []
  for name, value in _module_assigns(base / "cve_db.py"):
    if name == "CLIENT_SIDE_CVE_IDS":
      client = set(ast.literal_eval(value.args[0]))
    elif name == "CVE_DATABASE":
      for call in value.elts:
        a = [x.attr if isinstance(x, ast.Attribute) else ast.literal_eval(x) for x in call.args]
        kw = {k.arg: k.value for k in call.keywords}
        flag = isinstance(kw.get("applicability"), ast.Name) and kw["applicability"].id == "CLIENT_APPLICABILITY"
        rows.append((*a, *[""] * (6 - len(a)), flag))
  for name, value in _module_assigns(base / "cve_catalog_expansion.py"):
    if name == "EXPANDED_CVE_ROWS":
      rows += [(*r, False) for r in ast.literal_eval(value)]
  return {(p, c, cve, sev, title, cwe, int(flag or cve in client)) for p, c, cve, sev, title, cwe, flag in rows}


def test_static_cve_database_matches_overlay():
  overlay = json.loads((ROOT / "overlay/curated.json").read_text())["rows"]
  want = {tuple(r[f] for f in FIELDS) for r in overlay}
  have = _static_rows()
  assert have - want == set(), "in CVE_DATABASE, not in overlay"
  assert want - have == set(), "in overlay, not in CVE_DATABASE"
