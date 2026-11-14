"""redmesh-vulndb fetch|build|diff|gate"""
import argparse
import json
import sys
import time
from pathlib import Path

from . import build as build_mod
from . import diff as diff_mod
from . import fetch as fetch_mod


def _dump(obj):
  return json.dumps(obj, indent=1, sort_keys=True)


def cmd_fetch(a):
  if a.manifest_only:
    manifest = fetch_mod.write_manifest(a.cache)
  else:
    manifest = fetch_mod.fetch(a.cache, refresh=a.refresh)
  print(f"{len(manifest['inputs'])} inputs hashed into {Path(a.cache) / 'manifest.json'}")
  return 0


def cmd_build(a):
  if not a.offline:
    fetch_mod.fetch(a.cache)
  start = time.monotonic()
  record = build_mod.build(a.cache, a.out, root=a.root)
  record["build_seconds"] = round(time.monotonic() - start, 1)
  baseline = None
  if a.baseline:
    record["diff"] = diff_mod.diff_dbs(a.baseline, a.out)
    baseline = diff_mod.baseline_pairs(a.baseline)
  record["gates"] = diff_mod.run_gates(a.out, a.root, baseline=baseline)
  Path(str(a.out) + ".build.json").write_text(_dump(record) + "\n")
  failed = [k for k, v in record["gates"].items() if not v["ok"]]
  print(f"gates: {'FAILED ' + ', '.join(failed) if failed else 'all passed'}")
  return 1 if failed and not a.no_gate else 0


def cmd_diff(a):
  print(_dump(diff_mod.diff_dbs(a.old, a.new)))
  return 0


def cmd_gate(a):
  res = diff_mod.run_gates(a.db, a.root, baseline=diff_mod.baseline_pairs(a.baseline) if a.baseline else None)
  print(_dump(res))
  return 0 if all(v["ok"] for v in res.values()) else 1


def main(argv=None):
  p = argparse.ArgumentParser(prog="redmesh-vulndb")
  p.add_argument("--root", default=str(build_mod.ROOT), help="directory with product_map.toml, overlay/, eol.toml, allowlist/, tests/golden/ "
                                         "(default: the repository checkout, else the working directory)")
  sub = p.add_subparsers(dest="cmd", required=True)
  f = sub.add_parser("fetch", help="download the v1 feeds into a cache and hash them")
  f.add_argument("--cache", required=True)
  f.add_argument("--refresh", action="store_true", help="download again even when a file exists")
  f.add_argument("--manifest-only", action="store_true", help="hash what is in the cache, download nothing")
  f.set_defaults(fn=cmd_fetch)
  b = sub.add_parser("build", help="build the database from the cache and run the gates")
  b.add_argument("--cache", required=True)
  b.add_argument("--out", required=True)
  b.add_argument("--offline", action="store_true", help="read only the cache, no network; without it, files the cache lacks are fetched first "
                                                           "(none is refreshed: use `fetch --refresh`)")
  b.add_argument("--baseline", help="previous build to diff against (default: the overlay pairs)")
  b.add_argument("--no-gate", action="store_true", help="exit 0 even when a gate fails (results are still written)")
  b.set_defaults(fn=cmd_build)
  d = sub.add_parser("diff", help="diff two builds")
  d.add_argument("old")
  d.add_argument("new")
  d.set_defaults(fn=cmd_diff)
  g = sub.add_parser("gate", help="run the gates on a built database")
  g.add_argument("db")
  g.add_argument("--baseline", help="previous build for the lost-CVE gate (default: the overlay pairs)")
  g.set_defaults(fn=cmd_gate)
  a = p.parse_args(argv)
  return a.fn(a)


if __name__ == "__main__":
  sys.exit(main())
