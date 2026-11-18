import json
from pathlib import Path

from redmesh_vulndb.versions import MATCHER_REV, _matches_constraint, validate_constraint

GOLDEN = Path(__file__).parent / "golden"


def test_matcher_cases_from_edge_node():
  data = json.loads((GOLDEN / "matcher_cases.json").read_text())
  assert data["source_commit"] == "6bd9d71" and MATCHER_REV == "edge-node@6bd9d71"
  assert len(data["cases"]) == 38
  for c in data["cases"]:
    assert _matches_constraint(c["version"], c["constraint"], c["product"]) == c["expected"], c["why"]


def test_validate_constraint():
  assert validate_constraint(">=2.4.49,<2.4.51", "apache")
  assert validate_constraint("==9.18.24-S1", "bind")
  assert not validate_constraint(">=3.0,<2.0")  # inverted
  assert not validate_constraint("<abc")
  assert not validate_constraint("1.2.3")
  assert not validate_constraint("<")
