import json
import shutil
import sqlite3

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
