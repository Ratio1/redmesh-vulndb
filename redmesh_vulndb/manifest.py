"""manifest.json of a release, and the non-blocking flags.

The manifest is the only place with a timestamp (`built_at`). It describes the zstd asset (compressed by the
`zstd` CLI in the workflow: the Python stdlib has no zstd before 3.14) and the SQLite file inside it.
Flags are reported, never blocking.
"""
import datetime
import json
import sqlite3
from pathlib import Path

from . import fetch

SCHEMA = 1
# input folder -> the db `meta` key that names its snapshot
SNAPSHOT_KEY = {"nvd": "snapshot_nvd", "cvelist": "snapshot_cvelist", "overrides": "snapshot_nvd_overrides",
                "kev": "snapshot_kev", "epss": "snapshot_epss"}


def grype_crosscheck(grype_db):
  """Stub: cross-check of our CPE ranges for product-map products against the Grype DB. Never blocking."""
  if not grype_db:
    return {"status": "skipped", "reason": "no --grype-db given"}
  if not Path(grype_db).exists():
    return {"status": "skipped", "reason": f"Grype DB {grype_db} not found"}
  return {"status": "skipped", "reason": "cross-check not implemented yet (stub)"}


def flags(diff, spike_pct, spike_floor, grype_db):
  """KEV removals and additions, severity-band crossings, per-product change spikes, Grype cross-check.
  `diff` is diff_dbs output; None (no baseline) leaves the diff-based flags as None, meaning not computed.
  CNA identity is not stored in the database, so a per-CNA spike is not computed."""
  out = {"kev_added": None, "kev_removed": None, "band_changes": None, "product_spikes": None}
  if diff is not None:
    out["kev_added"], out["kev_removed"], out["band_changes"] = diff["kev_added"], diff["kev_removed"], diff["band_changes"]
    out["product_spikes"] = [[p, v["old"], v["added"], v["removed"]] for p, v in sorted(diff["by_product"].items())
                             if v["added"] + v["removed"] > max(spike_floor, v["old"] * spike_pct / 100)]
  out["grype_crosscheck"] = grype_crosscheck(grype_db)
  return out


def make(db, zst, cache, built_at=None, spike_pct=25, spike_floor=20, grype_db=None):
  """Manifest dict for `db` (with its `<db>.build.json`) and its compressed asset `zst`. Refuses a build with a failed gate."""
  db, zst = Path(db), Path(zst)
  record = json.loads(db.with_name(db.name + ".build.json").read_text())
  failed = sorted(k for k, v in record["gates"].items() if not v["ok"])
  if failed:
    raise ValueError(f"refusing a manifest: gate failed: {', '.join(failed)}")
  con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
  meta = dict(con.execute("SELECT k, v FROM meta"))
  con.close()
  cache_manifest = fetch.verify(cache)
  inputs = []
  for name in sorted(cache_manifest["inputs"]):
    entry = {"name": name, "sha256": cache_manifest["inputs"][name]["sha256"], "bytes": cache_manifest["inputs"][name]["bytes"]}
    entry["snapshot"] = meta.get(SNAPSHOT_KEY.get(name.split("/", 1)[0], ""), "")
    inputs.append(entry)
  return {
    "schema": SCHEMA, "build_id": record["build_id"],
    "built_at": built_at or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "asset": zst.name, "sha256": fetch.sha256_file(zst), "size_zst": zst.stat().st_size,
    "sha256_sqlite": record["sha256"], "size": record["bytes"], "content_hash": record["content_hash"],
    "inputs": inputs, "sources": cache_manifest.get("sources", {}), "gate_results": record["gates"],
    "flags": flags(record.get("diff"), spike_pct, spike_floor, grype_db),
  }
