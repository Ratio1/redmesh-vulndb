import json
import shutil
import sqlite3
from collections import Counter

import pytest

from redmesh_vulndb import build, diff, fetch
from redmesh_vulndb.versions import MATCHER_REV, _matches_constraint

from .conftest import FIXTURE_CACHE, PLAIN_ROOT, ROOT


def test_schema_and_meta(built, db):
  assert db.execute("PRAGMA user_version").fetchone()[0] == build.MODEL == 1
  assert db.execute("PRAGMA page_size").fetchone()[0] == build.PAGE_SIZE
  meta = dict(db.execute("SELECT k, v FROM meta"))
  assert meta["schema"] == "1.0.1" and meta["matcher_rev"] == MATCHER_REV == "edge-node@6bd9d71"
  assert meta["build_id"].startswith("vulndb-") and meta["epss_model_version"].startswith("v")
  assert meta["snapshot_nvd_overrides"] == "7c9258bb6d2ebb371a3b55b20a608f64c0e73753"
  assert [c[1] for c in db.execute("PRAGMA table_info(affected)")] == diff.expected_columns()["affected"]
  assert db.execute("SELECT count(*) FROM eol").fetchone()[0] == 9
  assert built[1]["counts"]["vuln"] == db.execute("SELECT count(*) FROM vuln").fetchone()[0]


def test_every_emitted_row_is_valid_and_has_a_vuln(db):
  assert db.execute("SELECT count(*) FROM affected WHERE cve_id NOT IN (SELECT cve_id FROM vuln)").fetchone()[0] == 0
  from redmesh_vulndb.versions import validate_constraint
  for product, cons in db.execute('SELECT product, "constraint" FROM affected'):
    assert validate_constraint(cons, product), (product, cons)
  assert db.execute("SELECT count(*) FROM vuln WHERE title=''").fetchone()[0] == 0


def test_confidence_and_source_rules(db):
  q = lambda s: db.execute(s).fetchall()  # noqa: E731
  assert q("SELECT DISTINCT confidence FROM affected WHERE source='curated'") == [("firm",)]
  assert q("SELECT DISTINCT confidence, reason FROM affected WHERE source='cna'") == [("tentative", "cna_range")]
  assert ("tentative", "nvd_exact") in q("SELECT DISTINCT confidence, reason FROM affected WHERE source='nvd'")
  assert ("firm", "nvd_range") in q("SELECT DISTINCT confidence, reason FROM affected WHERE source='nvd'")
  assert q("SELECT count(*) FROM affected WHERE source='nvd' AND \"constraint\" NOT LIKE '%<%' AND \"constraint\" NOT LIKE '==%'") == [(0,)]


def test_cna_rows_only_where_nvd_has_none(db):
  assert db.execute("SELECT count(*) FROM affected WHERE source='cna'").fetchone()[0] > 0
  for product, cve in db.execute("SELECT DISTINCT product, cve_id FROM affected WHERE source='cna'"):
    assert db.execute("SELECT count(*) FROM affected WHERE product=? AND cve_id=? AND source!='cna'", (product, cve)).fetchone()[0] == 0


def test_cna_only_cve_and_override_cve_present(db):
  assert db.execute("SELECT count(*) FROM affected WHERE cve_id='CVE-2026-57200' AND source='cna'").fetchone()[0] > 0
  assert db.execute("SELECT count(*) FROM affected WHERE cve_id='CVE-2023-52968' AND source='nvd'").fetchone()[0] > 0
  assert db.execute("SELECT count(*) FROM affected WHERE cve_id='CVE-2022-0866' AND product='jboss' AND source!='curated'").fetchone()[0] == 0


def test_kev_epss_cvss_and_title(db):
  row = db.execute("SELECT kev, kev_date_added, epss, epss_percentile, display_cvss_version, display_cvss_score, "
                   "display_cvss_source, title, published FROM vuln WHERE cve_id='CVE-2021-41773'").fetchone()
  assert row[0] == 1 and row[1] and row[2] > 0.5 and 0 < row[3] <= 1
  assert row[4] in ("3.1", "3.0", "4.0") and row[5] >= 7 and row[6] in ("cna", "nvd", "adp")
  assert 0 < len(row[7]) <= 120 and len(row[8]) == 10
  versions = {v for (v,) in db.execute("SELECT version FROM cvss WHERE cve_id='CVE-2021-41773'")}
  assert "3.1" in versions


def test_display_cvss_prefers_cna_v3():
  rows = [("3.1", "v-nvd", 9.8, "nvd"), ("3.1", "v-cna", 7.5, "cna"), ("4.0", "v4", 9.0, "cna")]
  assert build.display_cvss(rows) == ("3.1", 7.5, "cna")
  assert build.display_cvss([("3.1", "v", 5.0, "adp"), ("2.0", "v2", 9.0, "nvd")]) == ("3.1", 5.0, "adp")
  assert build.display_cvss([]) == (None, None, None)


def test_rejected_cve_becomes_a_tombstone(root_copy, tmp_path):
  data = json.loads((root_copy / "overlay/curated.json").read_text())
  data["rows"].append({"product": "openssh", "constraint": "<9.9", "cve_id": "CVE-2024-7633", "severity": "HIGH",
                       "title": "rejected test row", "cwe": "", "client_side": 0})
  data["row_count"] = len(data["rows"])
  (root_copy / "overlay/curated.json").write_text(json.dumps(data))
  out = tmp_path / "t.sqlite"
  build.build(FIXTURE_CACHE, out, root=root_copy, log=lambda *_: None)
  db = sqlite3.connect(out)
  assert db.execute("SELECT state FROM vuln WHERE cve_id='CVE-2024-7633'").fetchone() == ("REJECTED",)
  assert db.execute("SELECT count(*) FROM affected WHERE cve_id='CVE-2024-7633'").fetchone() == (0,)
  # the lost-CVE gate sees it: the overlay pair is gone and not on the allow-list
  res = diff.run_gates(out, root_copy)
  assert res["lost_cves"]["ok"] is False and ["openssh", "CVE-2024-7633"] in res["lost_cves"]["detail"]["unlisted"]
  with (root_copy / "allowlist/lost.tsv").open("a") as f:
    f.write("openssh\tCVE-2024-7633\trejected by NVD\n")
  assert diff.run_gates(out, root_copy)["lost_cves"]["ok"] is True


def test_build_is_offline_and_verifies_hashes(tmp_path):
  cache = tmp_path / "cache"
  shutil.copytree(FIXTURE_CACHE, cache)
  assert fetch.verify(cache)["inputs"]
  victim = next((cache / "kev").glob("*.json"))
  victim.write_text(victim.read_text() + " ")
  with pytest.raises(ValueError, match="sha256 mismatch"):
    build.build(cache, tmp_path / "x.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  (cache / "epss/epss_scores-current.csv.gz").unlink()
  with pytest.raises(FileNotFoundError):
    fetch.verify(cache)


def test_content_hash_is_over_rows_not_bytes(built, tmp_path):
  out, record = built
  assert build.content_hash(out) == record["content_hash"]
  copy = tmp_path / "copy.sqlite"
  con = sqlite3.connect(out)
  con.execute("VACUUM INTO ?", (str(copy),))
  con.close()
  assert build.content_hash(copy) == record["content_hash"]
  con = sqlite3.connect(copy)
  con.execute("UPDATE vuln SET kev=1 - kev WHERE cve_id='CVE-2021-41773'")
  con.commit()
  con.close()
  assert build.content_hash(copy) != record["content_hash"]


def test_matcher_reads_the_database(db):
  hit = [c for (c,) in db.execute("SELECT \"constraint\" FROM affected WHERE product='apache' AND cve_id='CVE-2021-41773'")]
  assert any(_matches_constraint("2.4.49", c, "apache") for c in hit)
  assert not any(_matches_constraint("2.4.51", c, "apache") for c in hit)


def test_component_cve_rule_drops_other_products_nvd_rows():
  row = lambda src: [src, "firm", "r", 0, 0]  # noqa: E731
  affected = {
    ("openssl", "CVE-1", "<1.1.1l"): row("nvd"),
    ("mysql", "CVE-1", "<5.7.36"): row("nvd"),       # dropped
    ("mariadb", "CVE-1", "<10.5"): row("nvd"),       # curated pair: kept
    ("nginx", "CVE-1", "<1.2"): row("cna"),          # not NVD: kept
    ("openssl", "CVE-2", "<1.0.2"): row("nvd"),
    ("jboss", "CVE-2", "<7"): row("nvd"),            # KEV: kept
    ("mysql", "CVE-3", "<5.7.1"): row("nvd"),        # no openssl row: kept
  }
  stats = build.Counter()
  dropped = build.drop_component_rows(affected, {("mariadb", "CVE-1")}, {"CVE-2": "2024-01-01"}, frozenset({"openssl"}), stats)
  assert dropped == {("mysql", "CVE-1")}
  assert stats["component_cve_dropped"] == 1
  assert ("mysql", "CVE-1", "<5.7.36") not in affected and len(affected) == 6


def test_supersede_pairs_listed_in_product_map():
  import tomllib
  pairs = tomllib.loads((ROOT / "product_map.toml").read_text())["supersede"]["pairs"]
  assert len(pairs) == 7 and ["apache", "CVE-2017-9798"] in pairs


def test_supersede_pair_needs_a_feed_range_row_else_curated(root_copy, tmp_path):
  """openssh CVE-2018-15473 has an NVD range row in the fixture, apache CVE-2021-41773 only an exact one, and
  CVE-9999-0001 none: only the first pair is replaced by the feed."""
  pm = root_copy / "product_map.toml"
  pm.write_text(pm.read_text().replace('pairs = [', 'pairs = [["openssh", "CVE-2018-15473"], ["apache", "CVE-2021-41773"], ["apache", "CVE-9999-0001"], ', 1))
  data = json.loads((root_copy / "overlay/curated.json").read_text())
  for cve, product in (("CVE-2018-15473", "openssh"), ("CVE-9999-0001", "apache")):
    data["rows"] = [r for r in data["rows"] if r["cve_id"] != cve]
    data["rows"].append({"product": product, "constraint": "<2.4.1", "cve_id": cve, "severity": "HIGH", "title": "t", "cwe": "", "client_side": 0})
  data["row_count"] = len(data["rows"])
  (root_copy / "overlay/curated.json").write_text(json.dumps(data))
  out = tmp_path / "b.sqlite"
  build.build(FIXTURE_CACHE, out, root=root_copy, log=lambda *_: None)
  con = sqlite3.connect(out)
  sources = lambda cve: {s for (s,) in con.execute("SELECT source FROM affected WHERE cve_id=?", (cve,))}  # noqa: E731
  assert sources("CVE-2018-15473") == {"nvd"}
  assert sources("CVE-2021-41773") == {"curated"}
  assert sources("CVE-9999-0001") == {"curated"}


def test_all_configured_supersede_pairs_supersede_in_real_data_shape():
  """The NVD rows of the 7 pairs in the 2026-11-14 full build: each has a range row, so the feed replaces curated.
  Exact-only pairs (an `==` row alone) stay curated."""
  import tomllib
  pairs = {tuple(p) for p in tomllib.loads((ROOT / "product_map.toml").read_text())["supersede"]["pairs"]}
  real = {("apache", "CVE-2017-9798"): ["<=2.2.34", "==2.4.0", "==2.4.1"], ("openssh", "CVE-2016-6210"): ["<=7.2"],
          ("mysql", "CVE-2016-6664"): [">=5.5.0,<=5.5.51"], ("jetty", "CVE-2023-36478"): [">=9.3.0,<9.4.53"],
          ("samba", "CVE-2023-3961"): ["<4.17.12"], ("postfix", "CVE-2023-51764"): ["<3.5.23"],
          ("elasticsearch", "CVE-2024-23450"): [">=7.0.0,<7.17.19"]}
  affected = {(p, c, cons): ["nvd"] for (p, c), conss in real.items() for cons in conss}
  assert set(real) == pairs and build.superseded_pairs(pairs, affected) == pairs
  exact_only = {("apache", "CVE-2017-9798", "==2.4.0"): ["nvd"]}
  assert build.superseded_pairs(pairs, exact_only) == set()


@pytest.mark.parametrize("desc, hit", [
  ("Apache for Win32 before 1.3.24, and 2.0.x before 2.0.34-beta, allows remote attackers", True),
  ("The rotatelogs program on Apache before 1.3.28, for Windows and OS/2 systems, does not", True),
  ("Apache 2.0 through 2.0.39 on Windows, OS2, and Netware allows remote attackers", True),
  ("Apache before 2.0.44, when running on unpatched Windows 9x and Me operating systems", True),
  ("Unknown vulnerability in filestat.c for Apache running on OS2, versions 2.0 through 2.0.45", True),
  ("Apache 1.3.29 and earlier, and Apache 2.0.48 and earlier, when running on Cygwin", True),
  ("Apache HTTP Server, when running on Linux with a document root on a Windows share mounted", False),
  ("Apache HTTP Server: DoS in HTTP/2 with initial windows size 0", False),
])
def test_non_unix_platform_rule_reads_the_nvd_description(desc, hit):
  # Old Apache CVEs carry no NVD platform node; the builder flags their rows platform_dependent from this rule.
  assert bool(build._NON_UNIX_PLATFORM.search(desc)) is hit


def test_builder_flags_an_apache_row_from_its_description(monkeypatch, tmp_path):
  # The fixture's one Apache NVD CVE, given a Win32 description and no platform node, must come out flagged.
  real = build.nvd.ingest
  def ingest(*a, **k):
    recs = real(*a, **k)
    r = recs["CVE-2001-0766"]
    r["description"] = "Apache for Win32 before 1.3.24 allows remote attackers to execute commands."
    r["rows"] = [(p, c, kind, 0) for p, c, kind, _ in r["rows"]]
    return recs
  monkeypatch.setattr(build.nvd, "ingest", ingest)
  out = tmp_path / "t.sqlite"
  build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  rows = sqlite3.connect(out).execute("SELECT platform_dependent FROM affected WHERE cve_id='CVE-2001-0766'").fetchall()
  assert rows and all(pd == 1 for (pd,) in rows)


def test_cna_quality_routing_in_the_builder(monkeypatch, tmp_path):
  # A `low` CNA row never lifts a floor; an `open` row is a floor for pairs NVD has and never a row of its own.
  real = build.cvelist.ingest
  def ingest(*a, **k):
    recs = real(*a, **k)
    recs["CVE-2018-15473"]["cna_rows"] = [("openssh", ">=7.0,<=7.7", "low")]  # NVD has `<=7.7`
    recs["CVE-2001-0001"] = {**recs["CVE-2018-15473"], "cna_rows": [("openssh", ">=1.3.0", "open")]}
    return recs
  monkeypatch.setattr(build.cvelist, "ingest", ingest)
  out = tmp_path / "t.sqlite"
  build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  con = sqlite3.connect(out)
  assert con.execute("SELECT count(*) FROM affected WHERE cve_id='CVE-2001-0001'").fetchone()[0] == 0
  assert con.execute("SELECT \"constraint\" FROM affected WHERE cve_id='CVE-2018-15473'").fetchall() == [("<=7.7",)]


def test_a_structured_cna_row_raises_the_floor_in_the_builder(monkeypatch, tmp_path):
  real = build.cvelist.ingest
  def ingest(*a, **k):
    recs = real(*a, **k)
    recs["CVE-2018-15473"]["cna_rows"] = [("openssh", ">=7.0,<=7.7", "medium")]  # NVD has `<=7.7`
    return recs
  monkeypatch.setattr(build.cvelist, "ingest", ingest)
  out = tmp_path / "t.sqlite"
  build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  con = sqlite3.connect(out)
  assert con.execute("SELECT \"constraint\" FROM affected WHERE cve_id='CVE-2018-15473'").fetchall() == [(">=7.0,<=7.7",)]


def _floors(prod, ranges, cna=(), exact=()):
  """Constraints left after raise_floors for NVD/override `ranges`, CNA constraints `cna`, NVD exact versions `exact`."""
  affected = {(prod, "CVE-X", c): ["nvd", "firm", "nvd_override", 0, 0] for c in ranges}
  affected.update({(prod, "CVE-X", f"=={v}"): ["nvd", "tentative", "nvd_exact", 0, 0] for v in exact})
  build.raise_floors(affected, {(prod, "CVE-X"): list(cna)}, Counter())
  return sorted(k[2] for k in affected if not k[2].startswith("=="))


def test_cna_floor_lifts_a_lower_or_missing_nvd_floor():
  # CVE-2026-97629, F5 form: 1.31.0<1.31.7, 1.30.0<1.30.6 and the open-ended 1.23.3 lessThan * (floor only, no row)
  cna = [">=1.31.0,<1.31.7", ">=1.30.0,<1.30.6", ">=1.23.3"]
  assert _floors("nginx", [">=0.1.29,<=0.9.9", ">=1.0.0,<1.30.6", ">=1.31.0,<1.31.7"], cna) == \
    [">=0.1.29,<=0.9.9", ">=1.23.3,<1.30.6", ">=1.31.0,<1.31.7"]  # the empty range is not emitted
  assert _floors("mysql", ["<5.7.19"], [">=5.7.0,<5.7.20"]) == [">=5.7.0,<5.7.19"]


def test_cna_floor_is_the_lowest_of_the_pair_and_needs_every_row_to_have_one():
  assert _floors("wordpress", [">=4.7,<5.4.1"], [">=4.7,<5.3", ">=5.4.0,<5.4.1"]) == [">=4.7,<5.4.1"]  # CVE-2020-11025
  assert _floors("wordpress", ["<5.4.1"], [">=5.4.0,<5.4.1", "<5.0"]) == ["<5.4.1"]  # one CNA row has no floor


def test_floor_is_not_raised_onto_a_row_the_pair_already_has():
  both = [">=9.11.3,<=9.18.50", ">=9.18.0,<=9.18.50"]
  assert _floors("bind", both, [">=9.18.0,<=9.18.50"]) == both  # CVE-2026-10723


def test_exact_row_floor_for_a_floorless_range():
  assert _floors("mysql", ["<=5.6.12"], exact=["5.6.3", "5.6.0"]) == [">=5.6.0,<=5.6.12"]  # CVE-2013-5767
  assert _floors("mysql", ["<5.6.12"], exact=["5.6.0"]) == [">=5.6.0,<5.6.12"]
  assert _floors("mysql", ["<=5.7.11"]) == ["<=5.7.11"]  # CVE-2016-0667: no exact rows


def test_exact_row_floor_needs_a_branch_start_on_one_branch_below_the_bound():
  assert _floors("wordpress", ["<=2.0.4"], exact=["2.0.2", "2.0.4"]) == ["<=2.0.4"]  # CVE-2006-5705: not a branch start
  assert _floors("mysql", ["<=5.6.12"], exact=["5.5.9", "5.6.0"]) == ["<=5.6.12"]  # another branch
  assert _floors("mysql", ["<=5.6.12"], exact=["5.6.0", "5.6.13"]) == ["<=5.6.12"]  # above the bound


def test_cna_floor_wins_over_the_exact_row_floor():
  assert _floors("mysql", ["<=5.6.12"], [">=5.6.0,<=5.6.12"], exact=["5.6.1"]) == [">=5.6.0,<=5.6.12"]
  assert _floors("mysql", ["<=5.6.12"], [">=5.5.0,<=5.6.12"], exact=["5.6.0"]) == [">=5.5.0,<=5.6.12"]
