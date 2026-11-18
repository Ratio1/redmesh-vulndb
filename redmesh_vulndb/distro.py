"""Distro-fix table: per distribution release and source package, did the distribution fix a CVE (RM-200).

Sources (both optional in the cache; `distro_map.toml` names the releases and the source packages per product):
  Ubuntu: Canonical CVE OVAL, one file per release (`oval/com.ubuntu.<release>.cve.oval.xml.bz2`), CC BY-SA 4.0.
  Debian: Security Tracker JSON (`debian/security-tracker.json`), all releases in one file.

Row rules. Only (product, CVE) pairs the build already has an `affected` row for get a row.
  Ubuntu: a CVE definition exists for the release. A source package listed in the release pocket as "has been fixed
    (note: 'V')" is `fixed` V; listed as "might be affected" is `open`. A package only listed in an ESM pocket
    (esm-infra, esm-apps: Ubuntu Pro) is `open` with no version: a host without Pro is not fixed. A package of the
    product that the release carries (it appears in some definition) but this definition does not list is
    `not_affected`. No definition for the CVE: no row (unknown).
  Debian: `resolved` with fixed_version "0" is `not_affected`, `resolved` with a version is `fixed`, `open` and
    `undetermined` are `open`. A package or release the tracker does not list for the CVE: no row.
"""
import bz2
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

NS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
CRITERION = re.compile(r"(\S+) source package in (\S+?), (.*)")
FIXED = re.compile(r"is affected and has been fixed \(note: '([^']*)'\)\.?")
VERSION = re.compile(r"[A-Za-z0-9.+~:_-]{1,100}")
CVE = re.compile(r"CVE-\d{4}-\d{4,}")
SOURCE = {"ubuntu": "ubuntu_oval", "debian": "debian_tracker"}


def package_matcher(spec):
  """Function: source package name -> product, from the `[packages]` table of distro_map.toml (full-match regexes);
  the first product in name order whose pattern matches, else None."""
  packages = {prod: [re.compile(p) for p in pats] for prod, pats in sorted(spec.items())}

  def find(name):
    for prod, pats in packages.items():
      if any(p.fullmatch(name) for p in pats):
        return prod
    return None
  return find


def parse_oval(path, release, product_of, wanted, stats):
  """Stream one Canonical OVAL file. Returns (defined, main, esm, seen).

  defined: wanted CVEs that have a vulnerability definition. main: {(cve, pkg): (status, version)} from the release
  pocket. esm: {(cve, pkg)} listed only in an ESM pocket of the release. seen: {pkg} of mapped products carried by
  the release (listed by any definition). Only mapped source packages are kept, so memory stays small."""
  defined, main, esm, seen = set(), {}, set(), set()
  defs = None
  with bz2.open(path, "rb") as f:
    for event, el in ET.iterparse(f, events=("start", "end")):
      if event == "start":
        defs = el if el.tag == f"{NS}definitions" else defs
        continue
      if el.tag == f"{NS}definitions":
        break  # the tests, objects and states sections after it are not read
      if el.tag != f"{NS}definition":
        continue
      if el.get("class") == "vulnerability":
        ref = next((r.get("ref_id") for r in el.iter(f"{NS}reference") if r.get("source") == "CVE"), None)
        if ref and CVE.fullmatch(ref):
          is_wanted = ref in wanted
          if is_wanted:
            defined.add(ref)
          for crit in el.iter(f"{NS}criterion"):
            m = CRITERION.fullmatch(crit.get("comment", ""))
            if not m or product_of(m.group(1)) is None:
              continue
            pkg, pocket, rest = m.groups()
            if pocket == release:
              esm_only = False
            elif pocket.startswith("esm-") and pocket.endswith("/" + release):
              esm_only = True
            else:
              continue
            seen.add(pkg)
            if not is_wanted:
              continue
            fixed = FIXED.fullmatch(rest)
            if not fixed and not rest.startswith("might be affected"):
              stats["oval_unknown_phrase"] += 1
            if esm_only:
              esm.add((ref, pkg))
            elif fixed and VERSION.fullmatch(fixed.group(1)):
              main[(ref, pkg)] = ("fixed", fixed.group(1))
            else:
              stats["oval_bad_version"] += bool(fixed)
              main[(ref, pkg)] = ("open", None)
      el.clear()
      defs.remove(el)  # the processed definition leaves the tree: memory stays flat
  return defined, main, esm, seen


def ubuntu_rows(release, parsed, product_of, wanted_by_product):
  defined, main, esm, seen = parsed
  rows = []
  for pkg in sorted(seen):
    prod = product_of(pkg)
    for cve in sorted(wanted_by_product.get(prod, frozenset()) & defined):
      if (cve, pkg) in main:
        status, ver = main[(cve, pkg)]
      elif (cve, pkg) in esm:
        status, ver = "open", None
      else:
        # Canonical's oval_lib.py (ubuntu-cve-tracker) emits needed, needs-triage, deferred, ignored and pending as "might be
        # affected" and released as fixed; it omits only DNE and not-affected. So a carried package absent here is one of those.
        status, ver = "not_affected", None
      rows.append(("ubuntu", release, prod, pkg, cve, status, ver, SOURCE["ubuntu"]))
  return rows


def debian_rows(path, releases, product_of, wanted_by_product, stats):
  with open(path, encoding="utf-8") as f:
    data = json.load(f)
  rows = []
  for pkg, cves in sorted(data.items()):
    prod = product_of(pkg)
    if prod is None:
      continue
    for cve in sorted(wanted_by_product.get(prod, frozenset()) & cves.keys()):
      for release in releases:
        entry = cves[cve].get("releases", {}).get(release)
        if not entry:
          continue
        status, ver = entry.get("status"), entry.get("fixed_version")
        if status == "resolved" and ver == "0":
          out = ("not_affected", None)
        elif status == "resolved" and isinstance(ver, str) and VERSION.fullmatch(ver):
          out = ("fixed", ver)
        elif status in ("open", "undetermined"):
          out = ("open", None)
        else:
          stats["debian_row_invalid_dropped"] += 1
          continue
        rows.append(("debian", release, prod, pkg, cve, *out, SOURCE["debian"]))
  return rows


def distro_fix_rows(cfg, inp, pairs, stats):
  """Rows of the distro_fix table, or None when the cache holds neither source (or no distro_map.toml exists)."""
  dm = cfg.get("distro")
  if not dm or not (inp["oval"] or inp["debian"]):
    return None
  product_of = package_matcher(dm["packages"])
  wanted = {}
  for prod, cve in pairs:
    wanted.setdefault(prod, set()).add(cve)
  wanted = {p: c for p, c in wanted.items() if p in dm["packages"]}
  all_wanted = set().union(*wanted.values()) if wanted else set()
  rows = []
  by_release = {p.name.split(".")[2]: p for p in inp["oval"]}  # com.ubuntu.<release>.cve.oval.xml.bz2
  for release in dm["ubuntu"]["releases"]:
    if release in by_release:
      parsed = parse_oval(by_release[release], release, product_of, all_wanted, stats)
      rows += ubuntu_rows(release, parsed, product_of, wanted)
  if stats["oval_unknown_phrase"] or stats["oval_bad_version"]:  # a wording change must not silently turn fixes into `open`
    raise ValueError(f"OVAL criterion not understood: {stats['oval_unknown_phrase']} unknown phrase(s), "
                     f"{stats['oval_bad_version']} bad version(s); update distro.py")
  if inp["debian"]:
    rows += debian_rows(inp["debian"][-1], dm["debian"]["releases"], product_of, wanted, stats)
  for (distro, release), n in Counter((r[0], r[1]) for r in rows).items():
    stats[f"distro_fix {distro} {release}"] = n
  return rows
