import json
from pathlib import Path

from redmesh_vulndb.versions import validate_constraint

ROOT = Path(__file__).resolve().parents[1]


def test_overlay_export_is_complete_and_valid():
  data = json.loads((ROOT / "overlay/curated.json").read_text())
  assert data["source_commit"] == "3205d18" and data["row_count"] == len(data["rows"]) == 374
  keys = {(r["product"], r["cve_id"], r["constraint"]) for r in data["rows"]}
  assert len(keys) == 374
  for r in data["rows"]:
    assert validate_constraint(r["constraint"], r["product"]), r
    assert r["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} and r["client_side"] in (0, 1)
  assert any(r["client_side"] for r in data["rows"])


def test_curated_rows_win_per_pair(db):
  curated = {tuple(r) for r in db.execute("SELECT DISTINCT product, cve_id FROM affected WHERE source='curated'")}
  overlay = json.loads((ROOT / "overlay/curated.json").read_text())["rows"]
  assert curated == {(r["product"], r["cve_id"]) for r in overlay}
  for product, cve in curated:
    assert {s for (s,) in db.execute("SELECT source FROM affected WHERE product=? AND cve_id=?", (product, cve))} == {"curated"}


def test_client_side_flag_follows_the_overlay(db):
  flagged = {c for (c,) in db.execute("SELECT DISTINCT cve_id FROM affected WHERE client_side=1")}
  overlay = json.loads((ROOT / "overlay/curated.json").read_text())["rows"]
  assert flagged == {r["cve_id"] for r in overlay if r["client_side"]}


def test_product_map_is_trimmed_to_probe_keys():
  import tomllib
  pm = tomllib.loads((ROOT / "product_map.toml").read_text())["products"]
  dead = set(json.loads((ROOT / "tests/golden/vulhub_expect.json").read_text())["dead_keys"])
  assert not dead & set(pm)
  assert pm["erlang_ssh"]["overlay_only"] is True and "nvd" not in pm["erlang_ssh"]
  assert "microsoft:iis" not in str(pm) and "windows_server_2022" not in pm
  assert "redislabs:redis" in pm["redis"]["nvd"] and "mysql:mysql" in pm["mysql"]["nvd"] and "mortbay:jetty" in pm["jetty"]["nvd"]
