"""RM-200 Phase 3a: the distro_fix table from Canonical OVAL and the Debian Security Tracker (small synthetic fixtures)."""
import bz2
import json
import shutil
import sqlite3
import tomllib
from collections import Counter

import pytest

from redmesh_vulndb import build, cli, diff, distro, fetch, manifest

from .conftest import FIXTURE_CACHE, PLAIN_ROOT, ROOT

DEFS = """<?xml version="1.0"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
  <definitions>
    <definition id="oval:com.ubuntu.jammy:def:100" class="inventory" version="1"><metadata><title>inv</title></metadata>
      <criteria><criterion test_ref="t:1" comment="openssh source package in jammy, is affected and has been fixed (note: 'x')." /></criteria></definition>
{body}
  </definitions>
  <tests><x/></tests>
</oval_definitions>
"""


def vuln(cve, *crits):
  c = "\n".join(f'<criterion test_ref="t:{i}" comment="{t}" />' for i, t in enumerate(crits))
  return (f'<definition id="oval:d:{cve}" class="vulnerability" version="1"><metadata><title>{cve}</title>'
          f'<reference source="CVE" ref_id="{cve}" ref_url="u" /></metadata><criteria operator="OR">{c}</criteria></definition>')


def oval(path, release, defs):
  path.parent.mkdir(parents=True, exist_ok=True)
  with bz2.open(path, "wb") as f:
    f.write(DEFS.format(body="\n".join(defs)).encode())


def write_ubuntu(path, release="jammy"):
  r = release
  oval(path, r, [
    vuln("CVE-2002-0083", f"openssh source package in {r}, is affected and has been fixed (note: '1:8.9p1-3ubuntu0.5').",
         f"openssh-ssh1 source package in {r}, might be affected and may need fixing.",
         f"paramiko source package in {r}, is affected and has been fixed (note: '2.9.3-0ubuntu1.2')."),
    vuln("CVE-2002-0639", f"openssh source package in {r}, might be affected and may need fixing."),
    vuln("CVE-2006-5051", f"putty source package in {r}, might be affected and may need fixing."),  # openssh absent: not_affected
    vuln("CVE-2009-1955", f"apache2 source package in esm-infra/{r}, is affected and has been fixed (note: '2.4.41-4ubuntu3.23+esm1')."),
    vuln("CVE-2004-0747", f"apache2 source package in esm-apps/{r}, might be affected and may need fixing.",
         f"apache2 source package in {r}, is affected and has been fixed (note: '2.4.52-1ubuntu4.1')."),
    vuln("CVE-2013-4547", f"memcached source package in {r}, might be affected and may need fixing."),  # product with no affected pair
    vuln("CVE-2099-0001", f"openssh source package in {r}, is affected and has been fixed (note: '1:9.9p1-1')."),
    vuln("CVE-2001-0766", f"apache2 source package in other/{r}, might be affected and may need fixing."),  # unknown pocket: ignored
  ])


def tracker(path):
  rel = lambda status, fixed=None: {"status": status, **({"fixed_version": fixed} if fixed else {})}  # noqa: E731
  data = {
    "openssh": {
      "CVE-2002-0083": {"releases": {"bookworm": rel("resolved", "1:9.2p1-2+deb12u2"), "trixie": rel("resolved", "0"), "sid": rel("open")}},
      "CVE-2002-0639": {"releases": {"bookworm": rel("open"), "trixie": rel("undetermined")}},
      "CVE-2099-0001": {"releases": {"bookworm": rel("open")}},  # no affected row in the build: no row
    },
    "apache2": {"CVE-2009-1955": {"releases": {"bookworm": rel("resolved", "2.4.57-1")}}},
    "unrelated": {"CVE-2002-0083": {"releases": {"bookworm": rel("open")}}},
    "openssh-ssh1": {},
  }
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_text(json.dumps(data))


@pytest.fixture
def distro_cache(tmp_path):
  """The fixture cache plus a jammy OVAL file and a tracker file, hashed into the manifest."""
  cache = tmp_path / "cache"
  shutil.copytree(FIXTURE_CACHE, cache)
  write_ubuntu(cache / "oval/com.ubuntu.jammy.cve.oval.xml.bz2")
  tracker(cache / "debian/security-tracker.json")
  fetch.write_manifest(cache)
  return cache


@pytest.fixture
def distro_root(root_copy):
  """A root whose distro_map.toml covers the synthetic fixtures (jammy only, and no golden facts)."""
  dm = tomllib.loads((ROOT / "distro_map.toml").read_text())
  text = ('[ubuntu]\nreleases = ["jammy"]\n[debian]\nreleases = ["bookworm", "trixie"]\n[packages]\n'
          + "".join(f"{k} = {json.dumps(v)}\n" for k, v in dm["packages"].items()))
  (root_copy / "distro_map.toml").write_text(text)
  return root_copy


def pathlib_write_oval(tmp_path):
  path = tmp_path / "j.oval.xml.bz2"
  oval(path, "jammy", [vuln("CVE-2002-0083", "openssh source package in jammy, is affected and was patched (note: 'x').")])
  return path


def rows_of(db):
  return {(r[0], r[1], r[3], r[4]): (r[5], r[6], r[7]) for r in db.execute("SELECT * FROM distro_fix")}


def test_ubuntu_three_statuses_absent_package_and_pockets(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  got = rows_of(sqlite3.connect(out))
  u = lambda pkg, cve: got.get(("ubuntu", "jammy", pkg, cve))  # noqa: E731
  assert u("openssh", "CVE-2002-0083") == ("fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval")
  assert u("openssh", "CVE-2002-0639") == ("open", None, "ubuntu_oval")
  assert u("openssh", "CVE-2006-5051") == ("not_affected", None, "ubuntu_oval")  # definition exists, package absent
  assert u("apache2", "CVE-2009-1955") == ("open", None, "ubuntu_oval")  # fix only in an ESM pocket: Pro, not a plain fix
  assert u("apache2", "CVE-2004-0747") == ("fixed", "2.4.52-1ubuntu4.1", "ubuntu_oval")  # release pocket wins over ESM
  assert u("apache2", "CVE-2001-0766") == ("not_affected", None, "ubuntu_oval")  # an unknown pocket counts as absent
  # not mapped to a product (paramiko, putty, openssh-ssh1): no rows
  assert not any(k[2] in ("paramiko", "putty", "openssh-ssh1", "memcached") for k in got)
  # CVE-2099-0001 has an OVAL definition but no affected row in the build; CVE-1999-1010 has an affected row but no definition
  assert not any(k[3] in ("CVE-2099-0001", "CVE-1999-1010") for k in got if k[0] == "ubuntu")
  assert {k[3] for k in got if k[0] == "ubuntu"} == {"CVE-2002-0083", "CVE-2002-0639", "CVE-2006-5051", "CVE-2009-1955", "CVE-2004-0747", "CVE-2001-0766"}


def test_parse_oval_counts_trusty_esm_pocket_as_esm(tmp_path):
  path = tmp_path / "t.oval.xml.bz2"
  oval(path, "trusty", [
    vuln("CVE-2020-35452", "apache2 source package in trusty/esm, is affected and has been fixed (note: '2.4.7-1ubuntu4.22+esm1')."),
    vuln("CVE-2014-0002", "apache2 source package in trusty/other, might be affected and may need fixing."),  # unknown pocket
  ])
  wanted = {"CVE-2020-35452", "CVE-2014-0002"}
  defined, main, esm, seen = distro.parse_oval(path, "trusty", lambda p: "apache" if p == "apache2" else None, wanted, Counter())
  assert defined == wanted and seen == {"apache2"} and main == {}
  assert esm == {("CVE-2020-35452", "apache2")}


def test_debian_statuses_and_missing_entries(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  got = rows_of(sqlite3.connect(out))
  d = lambda rel, pkg, cve: got.get(("debian", rel, pkg, cve))  # noqa: E731
  assert d("bookworm", "openssh", "CVE-2002-0083") == ("fixed", "1:9.2p1-2+deb12u2", "debian_tracker")
  assert d("trixie", "openssh", "CVE-2002-0083") == ("not_affected", None, "debian_tracker")  # resolved at "0"
  assert d("sid", "openssh", "CVE-2002-0083") is None  # release not configured
  assert d("bookworm", "openssh", "CVE-2002-0639") == ("open", None, "debian_tracker")
  assert d("trixie", "openssh", "CVE-2002-0639") == ("open", None, "debian_tracker")  # undetermined
  assert d("bookworm", "apache2", "CVE-2009-1955") == ("fixed", "2.4.57-1", "debian_tracker")
  assert d("bookworm", "openssh", "CVE-2099-0001") is None  # no affected row: no row
  assert not any(k[2] == "unrelated" for k in got)


def test_build_records_sources_and_schema(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  rec = build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  db = sqlite3.connect(out)
  meta = dict(db.execute("SELECT k, v FROM meta"))
  assert meta["schema"] == "1.0.1" and meta["snapshot_oval"] and meta["snapshot_debian"]
  assert {"oval/com.ubuntu.jammy.cve.oval.xml.bz2", "debian/security-tracker.json"} <= set(rec["inputs"])
  assert rec["counts"]["distro_fix"] == db.execute("SELECT count(*) FROM distro_fix").fetchone()[0] > 0
  assert [c[1] for c in db.execute("PRAGMA table_info(distro_fix)")] == [
    "distro", "release", "product", "package", "cve_id", "status", "fixed_version", "source"]


def test_build_is_deterministic_and_source_hash_changes_build_id(distro_cache, distro_root, tmp_path):
  a = build.build(distro_cache, tmp_path / "a.sqlite", root=distro_root, log=lambda *_: None)
  b = build.build(distro_cache, tmp_path / "b.sqlite", root=distro_root, log=lambda *_: None)
  assert a["content_hash"] == b["content_hash"] and a["build_id"] == b["build_id"]
  (distro_cache / "debian/security-tracker.json").write_text("{}")
  fetch.write_manifest(distro_cache)
  c = build.build(distro_cache, tmp_path / "c.sqlite", root=distro_root, log=lambda *_: None)
  assert c["build_id"] != a["build_id"]


def test_without_distro_map_the_table_is_empty_and_no_gate(built):
  assert built[1]["counts"].get("distro_fix", 0) == 0
  assert "distro_fix" not in diff.run_gates(built[0], PLAIN_ROOT)


def test_gate_fails_when_the_cache_lacks_the_sources(built, distro_root):
  """distro_map.toml configures releases: a build from a cache with no OVAL or tracker has zero rows, and the gate fails."""
  res = diff.run_gates(built[0], distro_root)["distro_fix"]
  assert not res["ok"] and res["detail"]["empty_releases"] == ["ubuntu:jammy", "debian:bookworm", "debian:trixie"]


def test_unknown_oval_phrase_fails_the_build(distro_cache, distro_root, tmp_path):
  oval(distro_cache / "oval/com.ubuntu.jammy.cve.oval.xml.bz2", "jammy", [
    vuln("CVE-2002-0083", "openssh source package in jammy, is affected and was patched (note: '1:8.9p1-3ubuntu0.5').")])
  fetch.write_manifest(distro_cache)
  with pytest.raises(ValueError, match="1 unknown phrase"):
    build.build(distro_cache, tmp_path / "o.sqlite", root=distro_root, log=lambda *_: None)


def test_oval_unknown_phrase_is_counted_as_open(tmp_path):
  stats = Counter()
  parsed = distro.parse_oval(pathlib_write_oval(tmp_path), "jammy", lambda n: "openssh" if n == "openssh" else None, {"CVE-2002-0083"}, stats)
  assert stats["oval_unknown_phrase"] == 1 and parsed[1][("CVE-2002-0083", "openssh")] == ("open", None)


def test_debian_resolved_without_version_is_dropped(tmp_path):
  p = tmp_path / "t.json"
  p.write_text(json.dumps({"openssh": {"CVE-2002-0083": {"releases": {"bookworm": {"status": "resolved"}}}}}))
  stats = Counter()
  assert distro.debian_rows(p, ["bookworm"], lambda n: "openssh", {"openssh": {"CVE-2002-0083"}}, stats) == []
  assert stats["debian_row_invalid_dropped"] == 1


def test_package_the_release_never_carries_has_no_rows(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  assert not any(k[1] == "jammy" and k[2] in ("postgresql-12", "php7.4", "nginx") for k in rows_of(sqlite3.connect(out)))


def test_gate_distro_empty_release_and_wrong_golden(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  db = diff.connect(out)
  good = [{"distro": "ubuntu", "release": "jammy", "package": "openssh", "cve_id": "CVE-2002-0083", "status": "fixed", "fixed_version": "1:8.9p1-3ubuntu0.5"},
          {"distro": "ubuntu", "release": "jammy", "package": "openssh", "cve_id": "CVE-2006-5051", "status": "not_affected"}]
  assert diff.gate_distro(db, good, {"ubuntu": ["jammy"], "debian": ["bookworm"]})["ok"]
  empty = diff.gate_distro(db, good, {"ubuntu": ["jammy", "focal"], "debian": ["bookworm"]})
  assert not empty["ok"] and empty["detail"]["empty_releases"] == ["ubuntu:focal"]
  bad = diff.gate_distro(db, [{**good[0], "fixed_version": "1:8.9p1-3ubuntu0.6"}, {**good[1], "cve_id": "CVE-2000-0000", "status": "fixed"}],
                         {"ubuntu": ["jammy"]})
  assert not bad["ok"] and len(bad["detail"]["golden_wrong"]) == 2


def test_run_gates_runs_distro_gate_with_the_root_map(distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  assert diff.run_gates(out, distro_root)["distro_fix"]["ok"]
  with open(distro_root / "distro_map.toml", "a") as f:
    f.write('[[golden]]\ndistro = "ubuntu"\nrelease = "jammy"\npackage = "openssh"\ncve_id = "CVE-2002-0083"\nstatus = "open"\n')
  assert not diff.run_gates(out, distro_root)["distro_fix"]["ok"]
  (distro_root / "distro_map.toml").write_text((distro_root / "distro_map.toml").read_text().replace('["jammy"]', '["jammy", "noble"]', 1))
  assert diff.run_gates(out, distro_root)["distro_fix"]["detail"]["empty_releases"] == ["ubuntu:noble"]


def test_diff_reports_distro_fix_counts(built, distro_cache, distro_root, tmp_path):
  out = tmp_path / "o.sqlite"
  build.build(distro_cache, out, root=distro_root, log=lambda *_: None)
  d = diff.diff_dbs(built[0], out)
  assert d["distro_fix"]["ubuntu:jammy"][0] == 0 and d["distro_fix"]["ubuntu:jammy"][1] > 0
  assert d["pairs"]["added"] == d["pairs"]["removed"] == 0  # existing tables unchanged


def test_real_distro_map_is_consistent():
  dm = tomllib.loads((ROOT / "distro_map.toml").read_text())
  pm = tomllib.loads((ROOT / "product_map.toml").read_text())["products"]
  assert set(dm["packages"]) - set(pm) == {"php", "dovecot"}  # in edge-node _BACKPORTED_PRODUCTS, not (yet) in the product map: no rows
  assert tuple(dm["ubuntu"]["releases"]) == fetch.UBUNTU_RELEASES
  find = distro.package_matcher(dm["packages"])
  assert find("openssh") == "openssh" and find("openssh-ssh1") is None and find("postgresql-14") == "postgresql"
  assert find("php8.1") == "php" and find("apache2") == "apache" and find("tomcat9") == "tomcat" and find("mariadb") == "mariadb"
  assert find("mariadb-10.6") == "mariadb" and find("mysql-8.0") == "mysql" and find("proftpd-dfsg") == "proftpd" and find("libssl3") is None
  for g in dm["golden"]:
    assert g["status"] in ("fixed", "not_affected", "open") and (g["status"] == "fixed") == ("fixed_version" in g)


def test_fetch_lists_the_distro_sources(tmp_path, monkeypatch):
  seen = []
  monkeypatch.setattr(fetch, "_download", lambda url, dest: seen.append(url))
  monkeypatch.setattr(fetch, "write_manifest", lambda *a, **k: {})
  for rel in [f"nvd/nvdcve-2.0-{y}.json.gz" for y in [*range(2002, 2100), "modified"]]:
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).touch()
  for rel in ("kev/kev.json", "epss/epss_scores-current.csv.gz", "cvelist/a.zip", "overrides/b.zip"):
    (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / rel).touch()
  fetch.fetch(tmp_path, log=lambda *_: None)
  plain = list(seen)
  seen.clear()
  fetch.fetch(tmp_path, log=lambda *_: None, elts=True)
  assert seen == plain + [fetch.ELTS_URL]
  assert plain == [f"https://security-metadata.canonical.com/oval/com.ubuntu.{r}.cve.oval.xml.bz2" for r in ("trusty", "focal", "jammy", "noble")] + [
    "https://security-tracker.debian.org/tracker/data/json"]


def elts_setup(distro_cache, distro_root, releases=("buster", "bullseye")):
  rel = lambda s, v=None: {"status": s, "fixed_version": v}  # noqa: E731
  (distro_cache / "elts").mkdir()
  (distro_cache / "elts/elts-tracker.json").write_text(json.dumps({"openssh": {  # the file also lists bookworm: only [debian_elts] releases are read
    "CVE-2002-0083": {"releases": {"buster": rel("resolved", "1:7.9p1-10+deb10u4"), "bullseye": rel("open"), "bookworm": rel("open")}}}}))
  (distro_root / "distro_map.toml").write_text((distro_root / "distro_map.toml").read_text().replace(
    "[packages]", f"[debian_elts]\nreleases = {json.dumps(list(releases))}\n[packages]"))


def test_elts_is_opt_in_and_adds_only_its_releases(distro_cache, distro_root, tmp_path):
  elts_setup(distro_cache, distro_root)
  fetch.write_manifest(distro_cache)  # without elts=True the file in the cache is not an input
  off = build.build(distro_cache, tmp_path / "off.sqlite", root=distro_root, log=lambda *_: None)
  assert not any(k.startswith("elts/") for k in off["inputs"])
  fetch.write_manifest(distro_cache, elts=True)
  on = build.build(distro_cache, tmp_path / "on.sqlite", root=distro_root, log=lambda *_: None)
  assert "elts/elts-tracker.json" in on["inputs"] and on["build_id"] != off["build_id"]
  got = {k: v for k, v in rows_of(sqlite3.connect(tmp_path / "on.sqlite")).items() if v[2] == "debian_elts_tracker"}
  assert got == {("debian", "buster", "openssh", "CVE-2002-0083"): ("fixed", "1:7.9p1-10+deb10u4", "debian_elts_tracker"),
                 ("debian", "bullseye", "openssh", "CVE-2002-0083"): ("open", None, "debian_elts_tracker")}
  assert diff.run_gates(tmp_path / "on.sqlite", distro_root)["distro_fix"]["detail"]["empty_releases"] == []  # buster, bullseye have rows


def test_elts_release_overlapping_the_debian_json_fails_the_build(distro_cache, distro_root, tmp_path):
  elts_setup(distro_cache, distro_root, releases=("bookworm", "buster"))
  fetch.write_manifest(distro_cache, elts=True)
  with pytest.raises(ValueError, match="both"):
    build.build(distro_cache, tmp_path / "o.sqlite", root=distro_root, log=lambda *_: None)


def build_cli(cache, root, out, *flags):
  return cli.main(["--root", str(root), "build", "--cache", str(cache), "--out", str(out), "--offline", *flags])


def test_golden_fact_of_elts_is_checked_only_when_elts_is_built(distro_cache, distro_root, tmp_path):
  elts_setup(distro_cache, distro_root)
  fact = ('\n[[golden]]\nelts = true\ndistro = "debian"\nrelease = "buster"\npackage = "openssh"\ncve_id = "CVE-2002-0083"\n'
          'status = "fixed"\nfixed_version = "1:7.9p1-10+deb10u4"\n')
  (distro_root / "distro_map.toml").write_text((distro_root / "distro_map.toml").read_text() + fact)
  fetch.write_manifest(distro_cache)
  assert build_cli(distro_cache, distro_root, tmp_path / "off.sqlite") == 0  # the fact is skipped: its source is off
  fetch.write_manifest(distro_cache, elts=True)
  assert build_cli(distro_cache, distro_root, tmp_path / "on.sqlite", "--elts") == 0
  (distro_root / "distro_map.toml").write_text((distro_root / "distro_map.toml").read_text().replace("1:7.9p1-10+deb10u4\"\n", "9\"\n"))
  assert build_cli(distro_cache, distro_root, tmp_path / "bad.sqlite", "--elts") == 1  # a wrong fact fails once the source is on


def test_build_elts_flag_must_match_the_cache_manifest(distro_cache, distro_root, tmp_path):
  elts_setup(distro_cache, distro_root)
  fetch.write_manifest(distro_cache)
  with pytest.raises(SystemExit, match="manifest names no ELTS"):
    build_cli(distro_cache, distro_root, tmp_path / "a.sqlite", "--elts")
  fetch.write_manifest(distro_cache, elts=True)
  with pytest.raises(SystemExit, match="names the ELTS input"):
    build_cli(distro_cache, distro_root, tmp_path / "b.sqlite")


def test_release_manifest_refuses_an_elts_build_without_the_override(distro_cache, distro_root, tmp_path, monkeypatch):
  elts_setup(distro_cache, distro_root)
  fetch.write_manifest(distro_cache, elts=True)
  db = tmp_path / "on.sqlite"
  assert build_cli(distro_cache, distro_root, db, "--elts") == 0
  zst = tmp_path / "x.zst"
  zst.write_bytes(b"x")
  monkeypatch.delenv(manifest.ELTS_RELEASE_ENV, raising=False)
  with pytest.raises(ValueError, match="Freexian ELTS"):
    manifest.make(db, zst, distro_cache, built_at="x")
  monkeypatch.setenv(manifest.ELTS_RELEASE_ENV, "1")
  assert manifest.make(db, zst, distro_cache, built_at="x")["build_id"]
