"""Fix round 1 regressions: exact rows, nested cvelist zip, input selection, constraint limits, stream chunks."""
import io
import json
import shutil
import zipfile
from collections import Counter

import pytest

from redmesh_vulndb import build, cvelist, fetch, nvd
from redmesh_vulndb.versions import validate_constraint

from .conftest import FIXTURE_CACHE, PLAIN_ROOT, ROOT


def _exact(prod, version, upd=""):
  st = Counter()
  return nvd.row_constraint(prod, version, upd, None, None, None, None, st), st


def test_exact_rows_keep_only_plain_release_forms():
  assert _exact("apache", "2.4.49")[0] == ("==2.4.49", "exact")
  assert _exact("openssl", "1.0.1", "f")[0] == ("==1.0.1f", "exact")
  assert _exact("bind", "9.18.24", "s1")[0] == ("==9.18.24-S1", "exact")
  assert _exact("bind", "9.16.3", "p2")[0] == ("==9.16.3-P2", "exact")
  assert _exact("openssh", "8.9", "p1")[0] == ("==8.9", "exact")
  for prod, ver, upd in [("drupal", "7.x-1.0", ""), ("drupal", "1.2.10netsec", ""), ("tomcat", "9.0.0", "sp1"),
                         ("apache", "2.4.1", "cp01"), ("apache", "2.4.1", "gamma"), ("apache", "1.0", "_rev1.15"),
                         ("apache", "1.0_rc1", ""), ("apache", "3.7.0alpha_1", ""), ("apache", "5.0", "-gold"),
                         ("apache", "1.0", "rc1"), ("mysql", "5.5.23", "a")]:
    got, st = _exact(prod, ver, upd)
    assert got is None, (prod, ver, upd)
    assert sum(v for k, v in st.items() if k.startswith("nvd_exact_")) == 1


def test_letter_release_list_matches_vendored_matcher():
  from redmesh_vulndb import versions
  assert tuple(nvd.LETTER_RELEASE) == tuple(versions._LETTER_RELEASE_PRODUCTS)


def test_cna_open_ended_expr_is_dropped():
  assert cvelist.cna_constraints("x", "expr", ">=1.0", None, None) == ([], None)
  assert cvelist.cna_constraints("x", "expr", ">=1.0, <2.0", None, None) == ([">=1.0,<2.0"], "medium")


def _nested(tmp_path, record):
  inner = io.BytesIO()
  with zipfile.ZipFile(inner, "w") as z:
    z.writestr("cves/2024/0xxx/CVE-2024-0001.json", json.dumps(record))
  path = tmp_path / "x_all_CVEs_at_midnight.zip.zip"
  with zipfile.ZipFile(path, "w") as z:
    z.writestr("cves.zip", inner.getvalue())
  return path


def test_cvelist_nested_zip_is_unwrapped(tmp_path):
  rec = {"cveMetadata": {"cveId": "CVE-2024-0001", "state": "PUBLISHED"}, "containers": {"cna": {}}}
  st = Counter()
  assert "CVE-2024-0001" in cvelist.ingest(_nested(tmp_path, rec), {}, {"CVE-2024-0001"}, st)
  assert st["cvelist_records"] == 1


def test_empty_feeds_raise(tmp_path):
  empty = tmp_path / "e.zip"
  with zipfile.ZipFile(empty, "w") as z:
    z.writestr("readme.txt", "x")
  with pytest.raises(ValueError, match="0 records"):
    cvelist.ingest(empty, {}, set(), Counter())
  import gzip
  g = tmp_path / "n.json.gz"
  with gzip.open(g, "wt") as f:
    f.write('{"vulnerabilities": []}')
  with pytest.raises(ValueError, match="0 vulnerabilities"):
    nvd.ingest([g], {}, {}, Counter())


def test_oversize_zip_member_raises(tmp_path, monkeypatch):
  monkeypatch.setattr(nvd, "MEMBER_LIMIT", 10)
  rec = {"cveMetadata": {"cveId": "CVE-2024-0001"}, "containers": {"cna": {}}}
  with pytest.raises(ValueError, match="too large"):
    cvelist.ingest(_nested(tmp_path, rec), {}, set(), Counter())


def test_stream_vulns_chunk_boundaries():
  doc = '{"format":"x","vulnerabilities":[{"cve":{"id":"A"}},{"cve":{"id":"B"}}],"tail":1}'
  for first in (1, 2, 5, 7, 23, 24, 25, 26, 27, 200):
    for more in (1, 3, 1000):
      assert [v["cve"]["id"] for v in nvd.stream_vulns(io.StringIO(doc), first, more)] == ["A", "B"], (first, more)
  assert list(nvd.stream_vulns(io.StringIO('{"vulnerabilities"'), 4, 4)) == []


def test_validate_constraint_limits():
  assert validate_constraint(">=1.0,<2.0", "x")
  assert validate_constraint(">=1.0,<=1.0", "x")
  assert not validate_constraint(">=1.0,<1.0", "x")
  assert not validate_constraint(">1.0,<=1.0", "x")
  assert not validate_constraint(">=2.0,<1.0", "x")
  assert not validate_constraint("<" + "1" * 70, "x")
  assert not validate_constraint(",".join(["<1.%d" % i for i in range(60)]), "x")
  assert not validate_constraint("<1.0;DROP", "x") and not validate_constraint("<1.0 2", "x")
  assert validate_constraint("<1.0.1f-S2+x~y_z", "x")


def _cache_with_two_overrides(tmp_path):
  cache = tmp_path / "cache"
  shutil.copytree(FIXTURE_CACHE, cache)
  old = next((cache / "overrides").glob("*.zip"))
  new = cache / "overrides/nvd-data-overrides-zzzz.zip"
  with zipfile.ZipFile(new, "w") as z:
    z.writestr("x/data/CVE-2099-0001.json", "{}")
  return cache, old, new


def test_build_uses_only_the_manifest_selected_files(tmp_path):
  cache, old, new = _cache_with_two_overrides(tmp_path)
  assert fetch.selected(cache, json.loads((cache / "manifest.json").read_text()))["overrides"] == old
  rec = build.build(cache, tmp_path / "a.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  base = build.build(FIXTURE_CACHE, tmp_path / "b.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  assert rec["content_hash"] == base["content_hash"]
  with pytest.raises(ValueError, match="more than one"):
    (cache / "manifest.json").unlink()
    fetch.write_manifest(cache)


def test_fetch_refresh_removes_superseded_files(tmp_path, monkeypatch):
  cache = tmp_path / "cache"
  shutil.copytree(FIXTURE_CACHE, cache)
  (cache / "cvelist/old_all_CVEs.zip").write_bytes(b"x")
  sha = "a" * 40

  class R(io.BytesIO):
    def __enter__(self):
      return self

    def __exit__(self, *a):
      pass

  def fake_open(url):
    if "releases" in url:
      asset = {"name": "new_all_CVEs.zip", "browser_download_url": "https://github.com/x/new.zip"}
      return R(json.dumps({"tag_name": "t1", "assets": [asset]}).encode())
    return R(json.dumps({"sha": sha}).encode())
  monkeypatch.setattr(fetch, "_open", fake_open)
  monkeypatch.setattr(fetch, "_download", lambda url, dest: dest.parent.mkdir(parents=True, exist_ok=True) or dest.write_bytes(b"d"))
  m = fetch.fetch(cache, refresh=True, log=lambda *_: None)
  assert [p.name for p in (cache / "cvelist").glob("*.zip")] == ["new_all_CVEs.zip"]
  assert [p.name for p in (cache / "overrides").glob("*.zip")] == [f"nvd-data-overrides-{sha}.zip"]
  assert m["sources"]["cvelist"] == {"file": "cvelist/new_all_CVEs.zip", "release": "t1"}
  assert m["sources"]["overrides"]["commit"] == sha


def test_fetch_rejects_bad_github_values(monkeypatch):
  with pytest.raises(ValueError):
    fetch.check_sha("not-a-sha")
  with pytest.raises(ValueError):
    fetch.check_asset("../evil.zip", "https://github.com/a/b.zip")
  with pytest.raises(ValueError):
    fetch.check_asset("ok.zip", "http://github.com/a/b.zip")
  with pytest.raises(ValueError):
    fetch.check_asset("ok.zip", "https://evil.example/a.zip")
  fetch.check_asset("2026_all_CVEs_at_midnight.zip.zip", "https://github.com/a/b.zip")


def test_shape_checks_null_or_drop_bad_feed_values():
  st = Counter()
  assert build.clean_str("CWE-79", build.CWE, st, "cwe") == "CWE-79"
  assert build.clean_str("NVD-CWE-Other", build.CWE, st, "cwe") is None and st["cwe_invalid"] == 1
  assert build.clean_str("2024-02-30", build.DATE, st, "published") is None and st["published_invalid"] == 1
  assert build.clean_str("2024-02-29", build.DATE, st, "published") == "2024-02-29"
  assert build.keep_cvss("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, st)
  assert build.keep_cvss("4.0", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3, st)
  assert build.keep_cvss("2.0", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5, st)
  assert not build.keep_cvss("3.1", "CVSS:3.0/AV:N", 5.0, st) and not build.keep_cvss("3.1", "<script>", 5.0, st)
  assert not build.keep_cvss("3.1", "CVSS:3.1/AV:N", 11, st)
  assert st["cvss_invalid_dropped"] == 3


def test_severity_overlay_else_band(db):
  assert db.execute("SELECT count(*) FROM vuln WHERE severity NOT IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO','UNKNOWN')").fetchone()[0] == 0
  assert build.band(None) == "UNKNOWN" and build.band(9.0) == "CRITICAL" and build.band(0) == "INFO" and build.band(3.9) == "LOW"
  for cve, sev in db.execute("SELECT cve_id, severity FROM vuln WHERE cve_id IN (SELECT cve_id FROM affected WHERE source='curated')"):
    overlay = {r["severity"] for r in json.loads((ROOT / "overlay/curated.json").read_text())["rows"] if r["cve_id"] == cve}
    assert sev in overlay


def test_build_id_includes_package_version(tmp_path, monkeypatch):
  a = build.build(FIXTURE_CACHE, tmp_path / "a.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  monkeypatch.setattr(build, "__version__", "9.9.9")
  b = build.build(FIXTURE_CACHE, tmp_path / "b.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  assert a["build_id"] != b["build_id"]


def test_content_hash_covers_the_ddl(built, tmp_path):
  import sqlite3
  copy = tmp_path / "c.sqlite"
  con = sqlite3.connect(built[0])
  con.execute("VACUUM INTO ?", (str(copy),))
  con.close()
  con = sqlite3.connect(copy)
  con.execute("PRAGMA writable_schema=ON")
  con.execute("UPDATE sqlite_master SET sql=sql || ' ' WHERE name='eol'")
  con.commit()
  con.close()
  assert build.content_hash(copy) != built[1]["content_hash"]


def test_cli_gate_baseline(built, capsys):
  from redmesh_vulndb import cli
  assert cli.main(["--root", str(PLAIN_ROOT), "gate", str(built[0]), "--baseline", str(built[0])]) == 0
  capsys.readouterr()


def test_cvss4_vector_with_long_values_is_kept():
  assert build.VECTOR.fullmatch("AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/U:Amber")
  assert build.VECTOR.fullmatch("AV:N/U:Clear")
  assert not build.VECTOR.fullmatch("AV:N/U:<script>")


def test_cna_expr_exact_part_follows_the_exact_row_rule():
  assert cvelist.cna_constraints("drupal", "expr", "= 7.x-1.0", None, None) == ([], None)
  assert cvelist.cna_constraints("apache", "expr", "= 2.4.49", None, None) == (["==2.4.49"], "medium")


def test_nested_cvelist_zip_over_the_limit_is_refused(tmp_path, monkeypatch):
  inner = io.BytesIO()
  with zipfile.ZipFile(inner, "w") as z:
    z.writestr("cves/2024/x/CVE-2024-0001.json", "{}")
  outer = tmp_path / "x.zip.zip"
  with zipfile.ZipFile(outer, "w") as z:
    z.writestr("cves.zip", inner.getvalue())
  monkeypatch.setattr(cvelist, "INNER_LIMIT", 10)
  with pytest.raises(ValueError):
    with cvelist.open_release(outer):
      pass


def test_manifest_file_outside_the_cache_is_refused(tmp_path):
  with pytest.raises(ValueError):
    fetch.selected(tmp_path, {"sources": {"cvelist": {"file": "../evil.zip"}}})
