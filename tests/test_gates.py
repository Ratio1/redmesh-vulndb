import json
import shutil
import sqlite3

import pytest

from redmesh_vulndb import cli, diff

from .conftest import ROOT


def test_all_gates_pass_on_fixture_build(built):
  res = diff.run_gates(built[0], ROOT)
  assert {k for k, v in res.items() if not v["ok"]} == set(), res
  assert set(res) == {"integrity", "schema", "t1_recall", "t2_first_fixed", "t3_above_max", "t4_matcher", "lost_cves", "size"}


def test_t1_recall_and_regressions(db):
  d = diff.gate_t1(db, ROOT / "tests/golden")["detail"]
  assert d["all"] == "33/33" and d["live"] == "26/26" and d["regressions_fixed"] == "9/9" and d["misses"] == []


def test_t1_excludes_the_node_only_backport_negative():
  expect = json.loads((ROOT / "tests/golden/vulhub_expect.json").read_text())
  assert [r for r in expect["rows"] if r["node_only"]] == [{"product": "openssh", "version": "8.9", "cve_id": "CVE-2024-6387", "node_only": True}]
  assert len(expect["rows"]) == 34


def test_t1_fails_when_a_regression_row_is_missing(built, tmp_path):
  bad = tmp_path / "bad.sqlite"
  src = sqlite3.connect(built[0])
  src.execute("VACUUM INTO ?", (str(bad),))
  con = sqlite3.connect(bad)
  con.execute("DELETE FROM affected WHERE cve_id='CVE-2017-12635'")
  con.commit()
  con.close()
  res = diff.gate_t1(diff.connect(bad), ROOT / "tests/golden")
  assert res["ok"] is False and res["detail"]["regressions_fixed"] == "8/9"


def test_t2_and_t3_catch_bad_rows(built, tmp_path):
  bad = tmp_path / "bad.sqlite"
  sqlite3.connect(built[0]).execute("VACUUM INTO ?", (str(bad),))
  con = sqlite3.connect(bad)
  con.execute("INSERT INTO affected VALUES('apache','>=2.4.0','CVE-2099-0001','cna','tentative','cna_range',0,0)")
  con.execute("INSERT INTO affected VALUES('apache','<abc','CVE-2099-0002','cna','tentative','cna_range',0,0)")
  con.commit()
  con.close()
  db = diff.connect(bad)
  assert diff.gate_t3(db)["ok"] is False and ["apache", "CVE-2099-0001"] == diff.gate_t3(db)["detail"][0][:2]
  assert diff.gate_t3(db, {("apache", "CVE-2099-0001"): "open-ended: test"})["ok"] is True
  assert diff.gate_t2(db)["ok"] is False


def test_t3_computes_from_the_database(db):
  assert diff.gate_t3(db)["ok"] is True
  assert diff._bump("apache", ["<2.4.58", ">=2.2.0,<=2.2.34"]) == "3.0.0"
  assert diff._bump("dropbear", ["<2022.83"]) == "2023"  # year.N versions


def test_t4_fails_on_a_wrong_expectation(tmp_path):
  g = tmp_path / "golden"
  shutil.copytree(ROOT / "tests/golden", g)
  data = json.loads((g / "matcher_cases.json").read_text())
  data["cases"][0]["expected"] = not data["cases"][0]["expected"]
  (g / "matcher_cases.json").write_text(json.dumps(data))
  assert diff.gate_t4(g)["ok"] is False


def test_integrity_gate_on_a_corrupt_file(tmp_path):
  bad = tmp_path / "bad.sqlite"
  bad.write_bytes(b"not a database" * 100)
  with pytest.raises(sqlite3.DatabaseError):
    diff.gate_integrity(diff.connect(bad))


def test_allowlist_needs_a_reason(tmp_path):
  p = tmp_path / "a.tsv"
  p.write_text("# c\nopenssl\tCVE-1\n")
  with pytest.raises(ValueError):
    diff.read_allowlist(p)
  p.write_text("openssl\tCVE-1\tfixed upstream\n*\tCVE-2\tnot a product CVE\n")
  allow = diff.read_allowlist(p)
  res = diff.lost_pairs({("openssl", "CVE-1"), ("apache", "CVE-2"), ("apache", "CVE-3")}, set(), allow)
  assert [r[:2] for r in res["allowed"]] == [["apache", "CVE-2"], ["openssl", "CVE-1"]] and res["unlisted"] == [["apache", "CVE-3"]]


def test_diff_reports_pairs_kev_and_bands(built, tmp_path):
  new = tmp_path / "new.sqlite"
  sqlite3.connect(built[0]).execute("VACUUM INTO ?", (str(new),))
  con = sqlite3.connect(new)
  con.execute("DELETE FROM affected WHERE product='memcached'")
  con.execute("UPDATE vuln SET kev=0 WHERE cve_id='CVE-2021-41773'")
  con.execute("UPDATE vuln SET display_cvss_score=3.0 WHERE cve_id='CVE-2014-0160'")
  con.commit()
  con.close()
  d = diff.diff_dbs(built[0], new)
  assert d["by_product"]["memcached"]["removed"] > 0 and d["by_product"]["memcached"]["added"] == 0
  assert d["kev_removed"] == ["CVE-2021-41773"] and d["kev_added"] == []
  assert any(c[0] == "CVE-2014-0160" and c[2] == "LOW" for c in d["band_changes"])
  assert diff.diff_dbs(built[0], built[0])["pairs"]["added"] == 0


def test_cli_gate_diff_and_build(built, tmp_path, capsys):
  assert cli.main(["gate", str(built[0])]) == 0
  assert cli.main(["diff", str(built[0]), str(built[0])]) == 0
  out = tmp_path / "v.sqlite"
  assert cli.main(["build", "--offline", "--cache", str(ROOT / "tests/fixtures/cache"), "--out", str(out)]) == 0
  rec = json.loads((tmp_path / "v.sqlite.build.json").read_text())
  assert rec["content_hash"] == built[1]["content_hash"] and rec["sha256"] == built[1]["sha256"]
  assert all(g["ok"] for g in rec["gates"].values())
  assert cli.main(["build", "--offline", "--cache", str(ROOT / "tests/fixtures/cache"), "--out", str(tmp_path / "w.sqlite"),
                   "--baseline", str(out)]) == 0
  assert json.loads((tmp_path / "w.sqlite.build.json").read_text())["diff"]["pairs"]["added"] == 0
  capsys.readouterr()


def test_cli_fetch_manifest_only(tmp_path):
  cache = tmp_path / "c"
  shutil.copytree(ROOT / "tests/fixtures/cache", cache)
  (cache / "manifest.json").unlink()
  assert cli.main(["fetch", "--cache", str(cache), "--manifest-only"]) == 0
  assert (cache / "manifest.json").exists()
