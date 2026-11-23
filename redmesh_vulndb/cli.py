"""redmesh-vulndb fetch|build|diff|gate|manifest"""
import argparse
import json
import sys
import time
from pathlib import Path

from . import build as build_mod
from . import diff as diff_mod
from . import fetch as fetch_mod
from . import manifest as manifest_mod


def _dump(obj):
  return json.dumps(obj, indent=1, sort_keys=True)


def cmd_fetch(a):
  if a.manifest_only:
    manifest = fetch_mod.write_manifest(a.cache, elts=a.elts)
  else:
    manifest = fetch_mod.fetch(a.cache, refresh=a.refresh, elts=a.elts)
  print(f"{len(manifest['inputs'])} inputs hashed into {Path(a.cache) / 'manifest.json'}")
  return 0


def _limits(a):
  return {"delta_pct": a.max_delta_pct, "delta_floor": a.delta_floor, "max_bytes": a.max_bytes}


def cmd_build(a):
  if not a.offline:
    fetch_mod.fetch(a.cache, elts=a.elts)
  if a.elts != fetch_mod.has_elts(json.loads((Path(a.cache) / "manifest.json").read_text())):
    raise SystemExit("--elts and the cache manifest disagree: " + (
      "the manifest names no ELTS input (run `fetch --elts`)" if a.elts else "the manifest names the ELTS input; build with --elts or rebuild the manifest without it"))
  start = time.monotonic()
  record = build_mod.build(a.cache, a.out, root=a.root, baseline_cves=diff_mod.baseline_cves(a.baseline) if a.baseline else frozenset())
  record["build_seconds"] = round(time.monotonic() - start, 1)
  baseline = None
  if a.baseline:
    record["diff"] = diff_mod.diff_dbs(a.baseline, a.out)
    baseline = diff_mod.baseline_pairs(a.baseline)
  record["gates"] = diff_mod.run_gates(a.out, a.root, baseline=baseline, limits=_limits(a),
                                   excused=record["stats"].get("component_dropped_pairs", []))
  Path(str(a.out) + ".build.json").write_text(_dump(record) + "\n")
  failed = [k for k, v in record["gates"].items() if not v["ok"]]
  print(f"gates: {'FAILED ' + ', '.join(failed) if failed else 'all passed'}")
  return 1 if failed and not a.no_gate else 0


def cmd_diff(a):
  print(_dump(diff_mod.diff_dbs(a.old, a.new)))
  return 0


def cmd_gate(a):
  record = Path(str(a.db) + ".build.json")  # the build's record names the pairs its component rule dropped
  excused = json.loads(record.read_text()).get("stats", {}).get("component_dropped_pairs", []) if record.exists() else []
  res = diff_mod.run_gates(a.db, a.root, baseline=diff_mod.baseline_pairs(a.baseline) if a.baseline else None, limits=_limits(a),
                           excused=excused)
  print(_dump(res))
  return 0 if all(v["ok"] for v in res.values()) else 1


def cmd_manifest(a):
  m = manifest_mod.make(a.db, a.zst, a.cache, built_at=a.built_at, spike_pct=a.max_delta_pct, spike_floor=a.delta_floor, grype_db=a.grype_db)
  Path(a.out).write_text(_dump(m) + "\n")
  print(f"manifest {a.out}: {m['build_id']} sha256={m['sha256'][:16]}")
  return 0


def _add_limits(p):
  p.add_argument("--max-delta-pct", type=float, default=diff_mod.LIMITS["delta_pct"], help="per-product pair change limit in %% of the baseline")
  p.add_argument("--delta-floor", type=int, default=diff_mod.LIMITS["delta_floor"], help="per-product change always allowed (tiny products)")
  p.add_argument("--max-bytes", type=int, default=diff_mod.LIMITS["max_bytes"], help="size limit of the uncompressed database")


def main(argv=None):
  p = argparse.ArgumentParser(prog="redmesh-vulndb")
  p.add_argument("--root", default=str(build_mod.ROOT), help="directory with product_map.toml, overlay/, eol.toml, allowlist/, tests/golden/ "
                                         "(default: the repository checkout, else the working directory)")
  sub = p.add_subparsers(dest="cmd", required=True)
  f = sub.add_parser("fetch", help="download the v1 feeds into a cache and hash them")
  f.add_argument("--cache", required=True)
  f.add_argument("--refresh", action="store_true", help="download again even when a file exists")
  f.add_argument("--manifest-only", action="store_true", help="hash what is in the cache, download nothing")
  f.add_argument("--elts", action="store_true", help="also fetch the Freexian ELTS tracker (buster, bullseye): local or canary builds only, never a release")
  f.set_defaults(fn=cmd_fetch)
  b = sub.add_parser("build", help="build the database from the cache and run the gates")
  b.add_argument("--cache", required=True)
  b.add_argument("--out", required=True)
  b.add_argument("--offline", action="store_true", help="read only the cache, no network; without it, files the cache lacks are fetched first "
                                                           "(none is refreshed: use `fetch --refresh`)")
  b.add_argument("--elts", action="store_true", help="include the Freexian ELTS tracker (fetched unless --offline): local or canary builds only, never a release")
  b.add_argument("--baseline", help="previous build to diff against (default: the overlay pairs)")
  b.add_argument("--no-gate", action="store_true", help="exit 0 even when a gate fails (results are still written)")
  _add_limits(b)
  b.set_defaults(fn=cmd_build)
  d = sub.add_parser("diff", help="diff two builds")
  d.add_argument("old")
  d.add_argument("new")
  d.set_defaults(fn=cmd_diff)
  g = sub.add_parser("gate", help="run the gates on a built database")
  g.add_argument("db")
  g.add_argument("--baseline", help="previous build for the lost-CVE gate (default: the overlay pairs)")
  _add_limits(g)
  g.set_defaults(fn=cmd_gate)
  m = sub.add_parser("manifest", help="write manifest.json for a built database and its zstd asset")
  m.add_argument("--db", required=True, help="built database; its .build.json supplies the gate results")
  m.add_argument("--zst", required=True, help="the zstd-compressed database (made with the zstd CLI)")
  m.add_argument("--cache", required=True)
  m.add_argument("--out", required=True)
  m.add_argument("--built-at", help="override the UTC timestamp (tests)")
  m.add_argument("--grype-db", help="Grype DB for the non-blocking cross-check (a stub: skipped with a reason)")
  m.add_argument("--max-delta-pct", type=float, default=diff_mod.LIMITS["delta_pct"], help="product spike flag, %% of the baseline")
  m.add_argument("--delta-floor", type=int, default=diff_mod.LIMITS["delta_floor"])
  m.set_defaults(fn=cmd_manifest)
  a = p.parse_args(argv)
  return a.fn(a)


if __name__ == "__main__":
  sys.exit(main())
