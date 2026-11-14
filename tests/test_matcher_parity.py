"""The vendored matcher equals the edge-node one. Needs EDGE_NODE_PATH (an edge-node checkout at 3205d18)."""
import ast
import json
import os
import re
import types
from pathlib import Path

import pytest

from redmesh_vulndb import versions

EDGE = os.environ.get("EDGE_NODE_PATH")
pytestmark = pytest.mark.skipif(not EDGE, reason="EDGE_NODE_PATH not set")
GOLDEN = Path(__file__).parent / "golden"


NAMES = {"_matches_constraint", "_parse_version", "_compare_versions", "_check_single", "_PRE_RANK", "_LETTER_RELEASE_PRODUCTS"}


@pytest.fixture(scope="module")
def real():
  """The matcher of the real cve_db.py, compiled from its source: the module itself needs edge-node's dependencies."""
  path = Path(EDGE) / "extensions/business/cybersec/red_mesh/cve_db.py"
  text = path.read_text()
  nodes = []
  for node in ast.parse(text).body:
    name = getattr(node, "name", None) or (getattr(node.targets[0], "id", None) if isinstance(node, ast.Assign) else None)
    if name in NAMES:
      nodes.append(node)
  ns = types.SimpleNamespace()
  scope = {"re": re}
  exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), scope)
  ns.__dict__.update({k: scope[k] for k in NAMES})
  ns.source = {n.name: ast.get_source_segment(text, n) for n in nodes if hasattr(n, "name")}
  return ns


def _probe_versions(constraint):
  """The bound versions of a constraint and a step above and below each."""
  out = set()
  for part in constraint.split(","):
    v = re.sub(r"^[<>=]+", "", part.strip())
    out.add(v)
    m = re.match(r"^(\d+(?:\.\d+)*)(.*)$", v)
    if m:
      nums = [int(x) for x in m.group(1).split(".")]
      for delta in (-1, 1):
        n = list(nums)
        n[-1] = max(0, n[-1] + delta)
        out.add(".".join(map(str, n)) + m.group(2))
  return out


def test_parity_on_matcher_cases(real):
  for c in json.loads((GOLDEN / "matcher_cases.json").read_text())["cases"]:
    args = (c["version"], c["constraint"], c["product"])
    assert versions._matches_constraint(*args) == real._matches_constraint(*args) == c["expected"]
    assert versions._parse_version(c["version"], c["product"]) == real._parse_version(c["version"], c["product"])


def test_parity_on_every_emitted_constraint(real, db):
  rows = db.execute('SELECT DISTINCT product, "constraint" FROM affected').fetchall()
  assert len(rows) > 300
  for product, constraint in rows:
    for version in _probe_versions(constraint):
      assert versions._matches_constraint(version, constraint, product) == real._matches_constraint(version, constraint, product), (product, constraint, version)
    for part in constraint.split(","):
      key = re.sub(r"^[<>=]+", "", part)
      assert versions._parse_version(key, product) == real._parse_version(key, product)


def test_vendored_source_is_verbatim(real):
  import inspect
  for name in ("_matches_constraint", "_parse_version", "_compare_versions", "_check_single"):
    assert inspect.getsource(getattr(versions, name)).strip() == real.source[name].strip(), name
  assert versions._PRE_RANK == real._PRE_RANK and versions._LETTER_RELEASE_PRODUCTS == real._LETTER_RELEASE_PRODUCTS
