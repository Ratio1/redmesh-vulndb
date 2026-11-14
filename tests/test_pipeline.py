"""RM-172 Phase 1: twice-build identity, baseline gates, tombstones, flags, manifest."""
import json
import sqlite3
from collections import Counter

import pytest

from redmesh_vulndb import build, cli, diff, manifest

from .conftest import FIXTURE_CACHE, ROOT


def copy_db(src, dst):
  sqlite3.connect(src).execute("VACUUM INTO ?", (str(dst),))
  return sqlite3.connect(dst)


def test_two_builds_from_the_same_inputs_are_identical(built, tmp_path):
  again = build.build(FIXTURE_CACHE, tmp_path / "again.sqlite", root=ROOT, log=lambda *_: None)
  assert again["content_hash"] == built[1]["content_hash"] and again["sha256"] == built[1]["sha256"]
  assert again["build_id"] == built[1]["build_id"]
  assert b"built_at" not in (tmp_path / "again.sqlite").read_bytes()


def test_row_delta_gate_limits_and_floor():
  old = Counter({"apache": 100, "tiny": 4, "gone": 50})
  assert diff.gate_row_delta(old, Counter({"apache": 120, "tiny": 4, "gone": 50}), pct=25, floor=10)["ok"]
  bad = diff.gate_row_delta(old, Counter({"apache": 130, "tiny": 4, "gone": 50}), pct=25, floor=10)
  assert not bad["ok"] and bad["detail"]["over"] == [["apache", 100, 130]]
  assert diff.gate_row_delta(old, Counter({"apache": 100, "tiny": 9, "gone": 50}), pct=25, floor=10)["ok"]  # floor: tiny product
  gone = diff.gate_row_delta(old, Counter({"apache": 100, "tiny": 4}), pct=25, floor=10)  # product vanished
  assert not gone["ok"] and gone["detail"]["over"] == [["gone", 50, 0]]


def test_size_gate(built):
  assert diff.gate_size(built[0], 32 * 2**20)["ok"]
  small = diff.gate_size(built[0], 1000)
  assert not small["ok"] and small["detail"]["bytes"] == built[0].stat().st_size


def test_baseline_gates_run_only_with_a_baseline(built):
  assert "row_delta" not in diff.run_gates(built[0], ROOT) and "size" in diff.run_gates(built[0], ROOT)
  res = diff.run_gates(built[0], ROOT, baseline=diff.baseline_pairs(built[0]))
  assert res["row_delta"]["ok"] and res["lost_cves"]["ok"]
  limits = {"delta_pct": 0, "delta_floor": 0, "max_bytes": 32 * 2**20}
  fewer = {(p, c) for p, c in diff.baseline_pairs(built[0])} | {("apache", f"CVE-2099-{i}") for i in range(5)}
  res = diff.run_gates(built[0], ROOT, baseline=fewer, limits=limits)
  assert not res["row_delta"]["ok"] and not res["lost_cves"]["ok"]


def test_baseline_tombstone_for_a_cve_that_lost_all_rows(tmp_path):
  # CVE-2024-7633 is rejected in the fixture feed and has no rows; with the baseline it is a REJECTED vuln row
  plain = tmp_path / "plain.sqlite"
  build.build(FIXTURE_CACHE, plain, root=ROOT, log=lambda *_: None)
  assert sqlite3.connect(plain).execute("SELECT 1 FROM vuln WHERE cve_id='CVE-2024-7633'").fetchone() is None
  out = tmp_path / "tomb.sqlite"
  rec = build.build(FIXTURE_CACHE, out, root=ROOT, log=lambda *_: None, baseline_cves={"CVE-2024-7633"})
  assert sqlite3.connect(out).execute("SELECT state FROM vuln WHERE cve_id='CVE-2024-7633'").fetchone() == ("REJECTED",)
  assert rec["stats"]["tombstones"] == 1 and rec["content_hash"] != build.content_hash(plain)


def test_lost_gate_excuses_a_tombstone_only_with_a_baseline(tmp_path):
  out = tmp_path / "tomb.sqlite"
  build.build(FIXTURE_CACHE, out, root=ROOT, log=lambda *_: None, baseline_cves={"CVE-2024-7633"})
  base = diff.baseline_pairs(out) | {("openssh", "CVE-2024-7633"), ("openssh", "CVE-2099-1")}
  res = diff.run_gates(out, ROOT, baseline=base)["lost_cves"]
  assert res["detail"]["tombstoned"] == 1 and res["detail"]["unlisted"] == [["openssh", "CVE-2099-1"]]
  only = diff.run_gates(out, ROOT, baseline=base - {("openssh", "CVE-2099-1")})["lost_cves"]
  assert only["ok"] is True


def test_baseline_cves_reads_both_states(built):
  ids = diff.baseline_cves(built[0])
  assert "CVE-2021-41773" in ids and len(ids) == built[1]["counts"]["vuln"]


def test_flags_report_and_never_block():
  d = {"kev_added": ["CVE-1"], "kev_removed": ["CVE-2"], "band_changes": [["CVE-3", "HIGH", "LOW"]],
       "by_product": {"apache": {"old": 100, "added": 60, "removed": 0}, "ssh": {"old": 100, "added": 2, "removed": 1}}}
  f = manifest.flags(d, spike_pct=25, spike_floor=10, grype_db=None)
  assert f["kev_removed"] == ["CVE-2"] and f["kev_added"] == ["CVE-1"] and f["band_changes"] == [["CVE-3", "HIGH", "LOW"]]
  assert f["product_spikes"] == [["apache", 100, 60, 0]]
  assert f["grype_crosscheck"]["status"] == "skipped" and f["grype_crosscheck"]["reason"]
  assert manifest.flags(None, 25, 10, None)["kev_removed"] is None  # no baseline: reported as not computed


def test_manifest_fields_and_determinism(built, tmp_path):
  zst = tmp_path / "vulndb.sqlite.zst"
  zst.write_bytes(b"fake zstd bytes")
  record = dict(built[1], gates=diff.run_gates(built[0], ROOT))
  built[0].with_name(built[0].name + ".build.json").write_text(json.dumps(record))
  m1 = manifest.make(built[0], zst, FIXTURE_CACHE, built_at="2026-11-14T00:00:00Z")
  m2 = manifest.make(built[0], zst, FIXTURE_CACHE, built_at="2030-01-01T00:00:00Z")
  assert {k: v for k, v in m1.items() if k != "built_at"} == {k: v for k, v in m2.items() if k != "built_at"}
  assert set(m1) == {"schema", "build_id", "built_at", "sha256", "sha256_sqlite", "content_hash", "size", "size_zst", "asset",
                     "inputs", "sources", "gate_results", "flags"}
  assert m1["built_at"] == "2026-11-14T00:00:00Z" and m1["build_id"] == built[1]["build_id"]
  assert m1["sha256"] != m1["sha256_sqlite"] == built[1]["sha256"] and m1["size_zst"] == 15 and m1["asset"] == "vulndb.sqlite.zst"
  assert m1["content_hash"] == built[1]["content_hash"] and m1["size"] == built[1]["bytes"]
  names = {i["name"]: i for i in m1["inputs"]}
  assert names["kev/kev.json"]["snapshot"] and all(len(i["sha256"]) == 64 for i in names.values())
  assert [i["name"] for i in m1["inputs"]] == sorted(names)
  assert m1["gate_results"]["integrity"]["ok"] is True


def test_manifest_refuses_a_failed_gate(built, tmp_path):
  zst = tmp_path / "v.zst"
  zst.write_bytes(b"x")
  record = dict(built[1], gates={"integrity": {"ok": False, "detail": []}})
  db = tmp_path / "v.sqlite"
  db.write_bytes(built[0].read_bytes())
  (tmp_path / "v.sqlite.build.json").write_text(json.dumps(record))
  with pytest.raises(ValueError, match="gate"):
    manifest.make(db, zst, FIXTURE_CACHE, built_at="x")


def test_cli_manifest_and_grype_skip(tmp_path, capsys):
  db, zst, out = tmp_path / "v.sqlite", tmp_path / "v.sqlite.zst", tmp_path / "manifest.json"
  assert cli.main(["build", "--offline", "--cache", str(FIXTURE_CACHE), "--out", str(db)]) == 0
  zst.write_bytes(b"z")
  assert cli.main(["manifest", "--db", str(db), "--zst", str(zst), "--cache", str(FIXTURE_CACHE), "--out", str(out)]) == 0
  m = json.loads(out.read_text())
  assert m["flags"]["grype_crosscheck"]["status"] == "skipped" and m["built_at"].endswith("Z")
  assert cli.main(["manifest", "--db", str(db), "--zst", str(zst), "--cache", str(FIXTURE_CACHE), "--out", str(out),
                   "--grype-db", str(tmp_path / "missing.db")]) == 0
  assert "not found" in json.loads(out.read_text())["flags"]["grype_crosscheck"]["reason"]
  capsys.readouterr()


def test_cli_build_with_baseline_records_tombstone_and_flags(built, tmp_path, capsys):
  out = tmp_path / "w.sqlite"
  assert cli.main(["build", "--offline", "--cache", str(FIXTURE_CACHE), "--out", str(out), "--baseline", str(built[0])]) == 0
  rec = json.loads((tmp_path / "w.sqlite.build.json").read_text())
  assert rec["gates"]["row_delta"]["ok"] and rec["diff"]["pairs"]["added"] == 0
  assert cli.main(["build", "--offline", "--cache", str(FIXTURE_CACHE), "--out", str(out), "--baseline", str(built[0]),
                   "--max-bytes", "10"]) == 1
  capsys.readouterr()


def test_row_delta_exempts_new_products_and_overrides():
  old = Counter({"apache": 100})
  assert diff.gate_row_delta(old, Counter({"apache": 100, "fresh": 500}), pct=25, floor=10)["ok"]  # new in the product map
  big = Counter({"apache": 300})
  assert not diff.gate_row_delta(old, big, pct=25, floor=10)["ok"]
  res = diff.gate_row_delta(old, big, pct=25, floor=10, exempt={"apache": "map rewrite"})
  assert res["ok"] and res["detail"]["exempt"] == ["apache"]


def test_row_delta_does_not_count_tombstoned_losses(tmp_path):
  out = tmp_path / "tomb.sqlite"
  build.build(FIXTURE_CACHE, out, root=ROOT, log=lambda *_: None, baseline_cves={"CVE-2024-7633"})
  base = diff.baseline_pairs(out) | {("openssh", "CVE-2024-7633")}
  strict = {"delta_pct": 0, "delta_floor": 0, "max_bytes": 32 * 2**20}
  res = diff.run_gates(out, ROOT, baseline=base, limits=strict)
  assert res["row_delta"]["ok"] and res["lost_cves"]["ok"] and res["lost_cves"]["detail"]["tombstoned"] == 1
  base = base | {("openssh", "CVE-2099-1")}  # a real loss still counts
  assert not diff.run_gates(out, ROOT, baseline=base, limits=strict)["row_delta"]["ok"]


def test_delta_override_file_needs_a_reason(root_copy):
  p = root_copy / "allowlist/delta.tsv"
  p.write_text("# product<TAB>reason\nopenssh\t\n")
  with pytest.raises(ValueError, match="reason"):
    diff.read_delta_overrides(p)
  p.write_text("# product<TAB>reason\nopenssh\tmap rewrite reviewed\n")
  assert diff.read_delta_overrides(p) == {"openssh": "map rewrite reviewed"}
  assert diff.read_delta_overrides(root_copy / "allowlist/none.tsv") == {}  # the file is optional
  db = root_copy / "v.sqlite"
  build.build(FIXTURE_CACHE, db, root=ROOT, log=lambda *_: None)
  base = {(p_, c) for p_, c in diff.baseline_pairs(db)} | {("openssh", f"CVE-2099-{i}") for i in range(50)}
  res = diff.run_gates(db, root_copy, baseline=base, limits={"delta_pct": 0, "delta_floor": 0, "max_bytes": 2**25})
  assert res["row_delta"]["ok"] and res["row_delta"]["detail"]["exempt"] == ["openssh"]


def test_github_api_requests_carry_the_token_only_when_set(monkeypatch):
  from redmesh_vulndb import fetch
  monkeypatch.delenv("GH_TOKEN", raising=False)
  monkeypatch.delenv("GITHUB_TOKEN", raising=False)
  assert fetch._request(fetch.CVELIST_API).get_header("Authorization") is None
  monkeypatch.setenv("GITHUB_TOKEN", "tok-b")
  assert fetch._request(fetch.CVELIST_API).get_header("Authorization") == "Bearer tok-b"
  monkeypatch.setenv("GH_TOKEN", "tok-a")
  assert fetch._request(fetch.OVERRIDES_API).get_header("Authorization") == "Bearer tok-a"
  # never sent to a download host, and dropped on a redirect to another host
  assert fetch._request(fetch.NVD_BASE + "x").get_header("Authorization") is None
  assert fetch._request(fetch.OVERRIDES_ZIP + "a" * 40).get_header("Authorization") is None
  req = fetch._request(fetch.CVELIST_API)
  new = fetch._HttpsOnly().redirect_request(req, None, 302, "Found", {}, "https://objects.example.com/x")
  assert new.get_header("Authorization") is None
  same = fetch._HttpsOnly().redirect_request(req, None, 302, "Found", {}, "https://api.github.com/other")
  assert same.get_header("Authorization") == "Bearer tok-a"
