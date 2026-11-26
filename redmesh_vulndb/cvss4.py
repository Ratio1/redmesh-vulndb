"""CVSS v4.0 score of a vector, by the `cvss` library (pinned in pyproject.toml), behind strict input checks (RM-170).

The library accepts out-of-order vectors, raises generic errors on non-str input and echoes the whole vector in its
messages. This wrapper rejects those cases with `V4VectorError`, whose message never contains the input.
Scores are Red Hat half-up rounded: 0.1 above the FIRST calculator on about 0.34% of vectors, no band change.
The value is the score of the vector as given: base (CVSS-B), or BT/BE/BTE when the vector itself carries threat or
environmental metrics. The build never adds a Threat metric (RM-268 D59).
"""
from cvss import CVSS4
from cvss.constants4 import METRICS, METRICS_MANDATORY

MAX_LEN = 200
PREFIX = "CVSS:4.0/"
_ORDER = {m: i for i, m in enumerate(METRICS)}  # spec Table 23


class V4VectorError(ValueError):
  """The vector is not a well-formed, correctly ordered CVSS:4.0 vector."""


def score_v4(vector):
  """The CVSS v4.0 score (0.0-10.0) of `vector`; raises V4VectorError for anything else."""
  if not isinstance(vector, str):
    raise V4VectorError(f"CVSS v4 vector must be str, got {type(vector).__name__}")
  if len(vector) > MAX_LEN:
    raise V4VectorError(f"CVSS v4 vector longer than {MAX_LEN} characters")
  if not vector.startswith(PREFIX):
    raise V4VectorError("CVSS v4 vector lacks the CVSS:4.0/ prefix")
  keys = [field.split(":", 1)[0] for field in vector[len(PREFIX):].split("/")]
  if any(k not in _ORDER for k in keys):
    raise V4VectorError("CVSS v4 vector has an unknown metric")
  if any(_ORDER[a] >= _ORDER[b] for a, b in zip(keys, keys[1:])):
    raise V4VectorError("CVSS v4 vector metrics are duplicated or out of order")
  if keys[:len(METRICS_MANDATORY)] != METRICS_MANDATORY:
    raise V4VectorError("CVSS v4 vector lacks a mandatory base metric")
  try:
    return float(CVSS4(vector).base_score)
  except Exception as e:  # the library's own messages echo the input: drop them
    raise V4VectorError(f"CVSS v4 vector rejected by the scorer ({type(e).__name__})") from None
