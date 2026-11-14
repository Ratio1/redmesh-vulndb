"""Vendored version matcher.

Copied verbatim from edge-node ``extensions/business/cybersec/red_mesh/cve_db.py``
(``_matches_constraint``, ``_parse_version``, ``_compare_versions``, ``_check_single`` and the
tables they use) at commit f763995. A matcher fix in edge-node bumps both copies in one
cross-repo change; ``tests/test_matcher_parity.py`` compares them when EDGE_NODE_PATH is set.
Only the header and ``validate_constraint`` below are builder code.
"""
import re

MATCHER_REV = "edge-node@f763995"


def _matches_constraint(version: str, constraint: str, product: str = "") -> bool:
  """Parse version constraint string and compare.

  Supports: ``<1.4.3``, ``>=2.4.49,<2.4.51``, ``<7.0``.
  Comma-separated constraints are ANDed. ``product`` selects the product-specific
  reading of single-letter release tags (see ``_parse_version``).
  """
  parts = [c.strip() for c in constraint.split(",")]
  parsed = _parse_version(version, product)
  if parsed is None:
    return False
  for part in parts:
    if not _check_single(parsed, part, product):
      return False
  return True


# Pre-release tags sort BEFORE the release they precede. Ascending rank:
# dev < alpha < beta < milestone < rc/pre; `a`/`b` are alpha/beta.
_PRE_RANK = {
  "dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2,
  "milestone": 3, "m": 3, "rc": 4, "pre": 4,
}
# Products whose single-letter suffix is a release (openssl 1.0.1f, proftpd
# 1.3.5b), not a pre-release.
_LETTER_RELEASE_PRODUCTS = ("openssl", "proftpd", "samba")


def _parse_version(version: str, product: str = ""):
  """Reduce a banner or constraint version to a comparable key ``(numbers, tail)``.

  Handles values like ``Apache/2.4.57 (Ubuntu)``, ``OpenSSH_8.9p1``,
  ``nginx/1.22.1``, ``1:8.9p1-3ubuntu0.10`` and pre-releases such as
  ``3.0.0rc1``, ``1.4.3-beta``, ``9.0.0.M1``, ``8.1.0-dev``.

  ``tail`` orders what follows the numbers: a pre-release ``(-1, tag, n)`` sorts
  before the release ``(0, 0, 0)``; a letter suffix ``9.8p1`` / ``1.0.1f`` or a
  BIND edition or patch level (``-S1``, ``-P4``) sorts after it. Compare keys with ``_compare_versions``.
  """
  if not isinstance(version, str):
    return None
  # Banners are untrusted: bound the work and the digit runs `int()` must parse.
  version = version[:128].strip()
  # Strip a Debian/RPM epoch before searching. `1:8.9p1-3ubuntu0.10` otherwise
  # matches on the leading `1` and returns (1,), reading the epoch as the
  # upstream version — which makes an OpenSSH 8.9 host match every CVE for 1.x.
  version = re.sub(r"^\s*\d+:", "", version)
  m = re.search(r"(\d+(?:\.\d+)*)(.*)$", version, re.DOTALL)
  if not m:
    return None
  numbers = [int(x) for x in m.group(1).split(".")]
  rest = m.group(2).lower()
  tail = (0, 0, 0)
  # `(?![a-z])`: the tag ends there, so `-precise` and `-devel` are not `pre` and `dev`.
  pre = re.match(r"^[-_.~]?(alpha|beta|rc|pre|dev|milestone|m|a|b)(\d*)(?![a-z])", rest)
  if pre:
    tag, num = pre.group(1), pre.group(2)
    # A bare single letter is a release letter, not a pre-release, unless a
    # number follows (`1.0a1`, `9.0.0.M1`) and the product does not use letter
    # releases.
    single = len(tag) == 1
    if (not single or num) and not (single and product in _LETTER_RELEASE_PRODUCTS):
      tail = (-1, _PRE_RANK[tag], int(num or 0))
  if tail == (0, 0, 0):
    edition = re.match(r"^-([sp])(\d+)(?![a-z0-9])", rest)  # BIND `-S1` edition, `-P4` patch level
    letter = re.match(r"^([a-z]{1,2})(\d*)(?=$|[-_.~+ ])", rest)  # 1.0.1f, 8.9p1, 1.3.5b
    if edition:
      tail = (1, ord(edition.group(1)) - 96, int(edition.group(2)))
    elif letter:
      value = 0
      for char in letter.group(1):
        value = value * 26 + ord(char) - 96
      tail = (1, value, int(letter.group(2) or 0))
  return numbers, tail


def _compare_versions(a, b) -> int:
  """Three-way compare of two ``_parse_version`` keys."""
  na, ta = a
  nb, tb = b
  size = max(len(na), len(nb))
  na = na + [0] * (size - len(na))
  nb = nb + [0] * (size - len(nb))
  if na != nb:
    return -1 if na < nb else 1
  return (ta > tb) - (ta < tb)


def _check_single(parsed, expr: str, product: str = "") -> bool:
  """Evaluate one comparison like '<1.4.3' or '>=2.4.49'."""
  m = re.match(r"(>=|<=|>|<|==)(.+)", expr.strip())
  if not m:
    return False
  op, ver_str = m.group(1), m.group(2)
  target = _parse_version(ver_str, product)
  if target is None:
    return False
  c = _compare_versions(parsed, target)
  if op == "<":
    return c < 0
  elif op == "<=":
    return c <= 0
  elif op == ">":
    return c > 0
  elif op == ">=":
    return c >= 0
  elif op == "==":
    return c == 0
  return False


def validate_constraint(constraint: str, product: str = "") -> bool:
  """True when every clause parses (64 chars at most, 256 for all, version charset), and no range is empty."""
  if len(constraint) > 256:
    return False
  lows, highs = [], []
  for part in constraint.split(","):
    part = part.strip()
    m = re.fullmatch(r"(>=|<=|>|<|==)([0-9A-Za-z._\-+~]+)", part)
    key = _parse_version(m.group(2), product) if m and len(part) <= 64 else None
    if key is None:
      return False
    if m.group(1) in (">=", ">"):
      lows.append((key, m.group(1) == ">"))
    elif m.group(1) in ("<", "<="):
      highs.append((key, m.group(1) == "<"))
  return not any((c := _compare_versions(lo, hi)) > 0 or (c == 0 and (lx or hx)) for lo, lx in lows for hi, hx in highs)
