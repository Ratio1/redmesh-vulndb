import json
from pathlib import Path

from redmesh_vulndb.versions import _matches_constraint, validate_constraint

ROOT = Path(__file__).resolve().parents[1]


def test_overlay_export_is_complete_and_valid():
  data = json.loads((ROOT / "overlay/curated.json").read_text())
  assert data["source_commit"] == "3205d18" and data["row_count"] == len(data["rows"]) == 378
  keys = {(r["product"], r["cve_id"], r["constraint"]) for r in data["rows"]}
  assert len(keys) == 378
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


# httpd.apache.org/security/vulnerabilities_24.html (fetched 2026-11-22): (CVE, versions inside, versions outside)
APACHE_RANGES = {
  "CVE-2024-40725": (("2.4.60", "2.4.61"), ("2.4.43", "2.4.49", "2.4.50", "2.4.59", "2.4.62")),
  "CVE-2021-41773": (("2.4.49",), ("2.4.43", "2.4.48", "2.4.50", "2.4.51")),
  "CVE-2026-42356": (("2.4.60", "2.4.68"), ("2.4.43", "2.4.49", "2.4.50", "2.4.59", "2.4.69")),
  "CVE-2026-56449": (("2.4.68",), ("2.4.43", "2.4.49", "2.4.50", "2.4.67", "2.4.69")),
}


def test_apache_ranges_follow_the_apache_lists():
  rows = {r["cve_id"]: r for r in json.loads((ROOT / "overlay/curated.json").read_text())["rows"] if r["product"] == "apache"}
  for cve, (inside, outside) in APACHE_RANGES.items():
    for v in inside:
      assert _matches_constraint(v, rows[cve]["constraint"], "apache"), (cve, v)
    for v in outside:
      assert not _matches_constraint(v, rows[cve]["constraint"], "apache"), (cve, v)


# Windows-only Apache CVEs (Apache: "on Windows"); NVD gives them no Windows scope, so the overlay marks them.
WINDOWS_ONLY = {"CVE-2024-38472", "CVE-2025-59775", "CVE-2026-59685"}


def test_windows_only_rows_are_platform_dependent(db):
  overlay = {r["cve_id"]: r for r in json.loads((ROOT / "overlay/curated.json").read_text())["rows"] if r["product"] == "apache"}
  assert all(overlay[c].get("platform_dependent") == 1 for c in WINDOWS_ONLY)
  assert all(r.get("platform_dependent", 0) in (0, 1) for r in overlay.values())
  flagged = {c for (c,) in db.execute("SELECT cve_id FROM affected WHERE source='curated' AND platform_dependent=1")}
  assert flagged == {r["cve_id"] for r in json.loads((ROOT / "overlay/curated.json").read_text())["rows"] if r.get("platform_dependent")}
