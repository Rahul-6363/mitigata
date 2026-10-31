"""
elliot -- the investigative reasoning layer.

ChronoPath tells the analyst what it detected. This package reads what
ChronoPath already established -- the incident, its links, gaps, indicators and
the wider detection table -- and asks the questions an experienced, sceptical
analyst would: what does not fit, what was never looked at, what else could
explain this, and what to check next.

It adds nothing to detection, correlation or the 2.0 layer, and writes nothing
to the database. Its only state is the investigation memory, a JSON file per
incident under `investigations/`.

THE RULE THAT SHAPES EVERYTHING HERE: every statement is built from, and cites,
an item in the evidence pack (E1, L2, G3 ...). The deterministic analysts can
only quote values that exist. The optional language-model layer is checked
afterwards, and its answer is thrown away if it cites an ID, timestamp or
address that is not in the pack.

Modules:
  evidence    the citable evidence pack for one incident
  analysts    observations, each in the seven-part investigative format
  hypotheses  competing theories, with support, challenges and status
  critic      adversarial self-review of each theory
  memory      what has been examined, decided, done and rejected
  engine      Investigator: brief(), ask(), and the analyst's actions
"""

from .engine import Investigator, QUESTIONS  # noqa: F401
