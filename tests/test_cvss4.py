import json
import sqlite3
from collections import Counter
from pathlib import Path

import pytest
from cvss.constants4 import CVSS_LOOKUP_GLOBAL

from redmesh_vulndb import build, cvelist, nvd
from redmesh_vulndb.cvss4 import V4VectorError, score_v4
from tests.conftest import FIXTURE_CACHE, PLAIN_ROOT

DATA = Path(__file__).parent / "refdata"
BASE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_macrovector_table_matches_first_270():
  """The library lookup table equals the 270 entries of FIRST's cvss_lookup.js, exact."""
  first = json.loads((DATA / "first_macrovector_scores.json").read_text())
  assert len(first) == 270
  assert {k: float(v) for k, v in CVSS_LOOKUP_GLOBAL.items()} == first


def test_reference_vectors_score_exactly():
  """Regression check against the library's own reference vectors (not FIRST-generated)."""
  lines = (DATA / "cvss4_reference_vectors.txt").read_text().splitlines()
  assert len(lines) > 1000
  for line in lines:
    vector, expected = line.split(" - ")
    assert score_v4(vector) == float(expected), vector


@pytest.mark.parametrize("vector", [
  "", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:4.0/", BASE + "/",
  BASE.replace("AV:N", "ZZ:N"),                      # unknown metric
  BASE + "/E:Q",
  "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",  # out of order (the lib would accept)
  BASE + "/E:A/AV:N",                                # optional metric before... duplicated and out of order
  "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/E:A/SC:N/SI:N/SA:N",  # threat inside the base block
  BASE + "/" + "AV:N/" * 100,                        # over-long
])
def test_invalid_vectors_rejected_with_own_error(vector):
  with pytest.raises(V4VectorError):
    score_v4(vector)


MANDATORY = ["AV:N", "AC:L", "AT:N", "PR:N", "UI:N", "VC:H", "VI:H", "VA:H", "SC:N", "SI:N", "SA:N"]


def _vec(parts):
  return "CVSS:4.0/" + "/".join(parts)


@pytest.mark.parametrize("i", range(11))
def test_each_mandatory_metric_missing_unknown_or_duplicated_is_rejected(i):
  missing = MANDATORY[:i] + MANDATORY[i + 1:]
  unknown_value = MANDATORY[:i] + [MANDATORY[i][:-1] + "Z"] + MANDATORY[i + 1:]
  duplicate = MANDATORY[:i + 1] + [MANDATORY[i]] + MANDATORY[i + 1:]
  assert score_v4(_vec(MANDATORY)) >= 0
  for parts in (missing, unknown_value, duplicate):
    with pytest.raises(V4VectorError):
      score_v4(_vec(parts))


@pytest.mark.parametrize("value", [None, b"CVSS:4.0/AV:N", 4.0, ["x"]])
def test_non_str_rejected_with_own_error(value):
  with pytest.raises(V4VectorError):
    score_v4(value)


def test_error_does_not_echo_input():
  secret = "CVSS:4.0/AV:N/SECRET-" + "x" * 50
  with pytest.raises(V4VectorError) as e:
    score_v4(secret)
  assert "SECRET" not in str(e.value)


def test_known_scores():
  assert score_v4(BASE) == 9.3
  assert score_v4(BASE.replace("SC:N/SI:N/SA:N", "SC:H/SI:H/SA:H")) == 10.0
  assert score_v4(BASE + "/E:P") == 8.9


def test_rescore_replaces_feed_score_and_counts():
  stats = Counter()
  assert build.rescore("4.0", BASE, 9.3, stats) == 9.3
  assert build.rescore("4.0", BASE, 9.4, stats) == 9.3              # 0.1 gap: agreement, not flagged
  assert stats["cvss_v4_mismatch"] == 0
  assert build.rescore("4.0", BASE, 5.0, stats) == 9.3              # larger gap
  assert build.rescore("4.0", BASE, None, stats) == 9.3             # feed gave none: filled
  assert stats["cvss_v4_mismatch"] == 1 and stats["cvss_v4_recomputed"] == 4
  assert build.rescore("4.0", "CVSS:4.0/AC:L/AV:N", 9.0, stats) is None  # invalid: no score, not the feed's
  assert stats["cvss_v4_invalid"] == 1
  assert build.rescore("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, stats) == 9.8  # other versions untouched


def test_build_recomputes_v4_rows(tmp_path, monkeypatch):
  real = cvelist.ingest

  def ingest(*a, **k):
    recs = real(*a, **k)
    recs["CVE-2021-41773"]["cvss"] = list(recs["CVE-2021-41773"]["cvss"]) + [
      ("4.0", BASE, 1.0, "cna"), ("4.0", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.0, "adp")]
    return recs
  monkeypatch.setattr(cvelist, "ingest", ingest)
  out = tmp_path / "v.sqlite"
  record = build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  db = sqlite3.connect(out)
  rows = {src: score for src, score in db.execute("SELECT source, score FROM cvss WHERE cve_id='CVE-2021-41773' AND version='4.0'")}
  assert rows == {"cna": 9.3, "adp": None}
  assert record["stats"]["cvss_v4_mismatch"] == 1 and record["stats"]["cvss_v4_invalid"] == 1


def _feed_with(monkeypatch, entries):
  real = cvelist.ingest

  def ingest(*a, **k):
    recs = real(*a, **k)
    recs["CVE-2021-41773"]["cvss"] = list(recs["CVE-2021-41773"]["cvss"]) + entries
    return recs
  monkeypatch.setattr(cvelist, "ingest", ingest)


def test_duplicate_feed_entry_counts_once(tmp_path, monkeypatch):
  _feed_with(monkeypatch, [("4.0", BASE, 1.0, "cna"), ("4.0", BASE, 2.0, "cna")])
  record = build.build(FIXTURE_CACHE, tmp_path / "v.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
  assert record["stats"]["cvss_v4_recomputed"] == 1 and record["stats"]["cvss_v4_mismatch"] == 1


def test_nvd_sourced_v4_row_is_recomputed(tmp_path, monkeypatch):
  real = nvd.ingest

  def ingest(*a, **k):
    recs = real(*a, **k)
    recs["CVE-2021-41773"]["cvss"] = list(recs["CVE-2021-41773"]["cvss"]) + [("4.0", BASE, 2.0, "nvd")]
    return recs
  monkeypatch.setattr(nvd, "ingest", ingest)
  out = tmp_path / "v.sqlite"
  build.build(FIXTURE_CACHE, out, root=PLAIN_ROOT, log=lambda *_: None)
  score, = sqlite3.connect(out).execute("SELECT score FROM cvss WHERE cve_id='CVE-2021-41773' AND version='4.0' AND source='nvd'").fetchone()
  assert score == 9.3


def test_gate_fails_build_when_many_v4_vectors_are_unscorable(tmp_path, monkeypatch):
  bad = [("4.0", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:" + c, 5.0, "cna") for c in "APU"]
  bad += [("4.0", "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:%s" % c, 5.0, "adp") for c in "HLN"]
  _feed_with(monkeypatch, bad)
  with pytest.raises(RuntimeError, match="v4 scoring gate"):
    build.build(FIXTURE_CACHE, tmp_path / "v.sqlite", root=PLAIN_ROOT, log=lambda *_: None)
