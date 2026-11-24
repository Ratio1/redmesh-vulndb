from collections import Counter

from redmesh_vulndb import cvelist, fetch, nvd

from .conftest import FIXTURE_CACHE


def test_split_cpe_keeps_escapes():
  p = nvd.split_cpe(r"cpe:2.3:a:joomla:joomla\!:3.4.0:*:*:*:*:*:*:*")
  assert p[3:6] == ["joomla", r"joomla\!", "3.4.0"]


def test_norm_ver():
  assert nvd.norm_ver("openssh", "8.9p1") == "8.9"
  assert nvd.norm_ver("nginx", "R28") is None  # NGINX Plus
  assert nvd.norm_ver("tomcat", "9.0.35-3.39.1") is None  # package revision
  assert nvd.norm_ver("apache", "*") is None and nvd.norm_ver("apache", "2.4 beta") is None
  assert nvd.norm_ver("bind", "9.18.24-S1") == "9.18.24-S1"


def test_row_constraint_rules():
  st = Counter()
  rc = lambda *a: nvd.row_constraint(*a, st)  # noqa: E731
  assert rc("apache", "*", "*", "2.4.0", None, None, "2.4.50") == (">=2.4.0,<2.4.50", "range")
  assert rc("apache", "2.4.49", "*", None, None, None, None) == ("==2.4.49", "exact")
  assert rc("bind", "9.18.24", "s1", None, None, None, None) == ("==9.18.24-S1", "exact")
  assert rc("openssl", "1.0.1", "f", None, None, None, None) == ("==1.0.1f", "exact")  # letter release
  assert rc("tomcat", "10.1.0", "m1", None, None, None, None) is None  # pre-release
  assert rc("jboss", "*", "*", "7.1.0", None, None, None) is None  # lower bound alone is open-ended
  assert st["nvd_exact_prerelease_skip"] == 1 and st["nvd_open_ended_dropped"] == 1


def test_cna_classifier():
  assert cvelist.classify("2.0", "2.4.50", None, "semver", "affected", "unaffected") == "range"
  assert cvelist.classify("2.0", "*", None, "semver", "affected", "unaffected") == "range_open"
  assert cvelist.classify(">=1.0, <2.0", None, None, None, "affected", None) == "expr"
  assert cvelist.cna_constraints("x", "range", "0", "2.0", None) == (["<2.0"], "medium")
  assert cvelist.cna_constraints("x", "range", "1.0", None, "2.0") == ([">=1.0,<=2.0"], "medium")
  assert cvelist.cna_constraints("x", "range_open", "1.0", None, None) == ([">=1.0"], "open")  # open-ended: a floor for the builder, no row
  assert cvelist.cna_constraints("x", "range_open", "0", None, None) == ([], None)
  assert cvelist.cna_constraints("x", "exact", "1.2.3", None, None) == (["==1.2.3"], "low")
  assert cvelist.parse_freetext("Fixed in 3.0.3 (Affected 3.0.0,3.0.1)") == ["==3.0.0", "==3.0.1"]
  assert cvelist.parse_freetext("5.7.0 and prior") == [">=5.7,<=5.7.0"]


def test_cna_alias_pairs_are_exact():
  aliases = {("apache software foundation", "apache http server"): "apache"}
  cna = {"affected": [
    {"vendor": "Apache Software Foundation", "product": "Apache HTTP Server", "defaultStatus": "unaffected",
     "versions": [{"version": "2.0", "lessThan": "2.4.50", "status": "affected", "versionType": "semver"}]},
    {"vendor": "Apache Software Foundation", "product": "Apache HTTP Server Extra",
     "versions": [{"version": "1", "lessThan": "2", "status": "affected"}]},
  ]}
  rows = cvelist.cna_rows_of(cna, aliases, Counter())
  assert rows == [("apache", ">=2.0,<2.4.50", "medium")]


def test_overrides_layer_only_on_unanalysed_cves():
  cfg = _cfg()
  st = Counter()
  ov = nvd.load_overrides(fetch.inputs(FIXTURE_CACHE)["overrides"][-1], cfg["vp2prod"], st)
  assert {"CVE-2023-52968", "CVE-2024-0760"} <= set(ov)
  recs = nvd.ingest(fetch.inputs(FIXTURE_CACHE)["nvd"], cfg["vp2prod"], ov, st)
  assert recs["CVE-2023-52968"]["layer"] == "override" and recs["CVE-2023-52968"]["rows"]
  assert recs["CVE-2021-41773"]["layer"] == "nvd"  # analysed by NVD: the override is not used
  assert recs["CVE-2024-7633"]["rejected"]


def test_platform_dependent_rows_are_flagged(db):
  assert db.execute("SELECT count(*) FROM affected WHERE platform_dependent=1").fetchone()[0] > 0


def _cfg():
  from redmesh_vulndb import build
  return build.load_config(build.ROOT)
