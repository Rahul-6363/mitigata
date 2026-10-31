"""
chronopath2 -- the ChronoPath 2.0 evidence-and-gap layer.

WHY THIS PACKAGE EXISTS
-----------------------
ChronoPath 1.x answers "what happened?" It streams millions of log lines,
detects technique-level activity, correlates it into incidents and ranks them.
That is the detection problem, and it is solved: 100% detection and 100%
correct ATT&CK labels on the organisers' 6.54 GB FortiGate file.

But an analyst handed a ranked incident list still cannot act on it, because
three questions remain unanswered:

    "Why do you think these events belong together?"
    "What couldn't you see?"
    "What do I do in the next ten minutes?"

A tool that cannot answer those is a tool an analyst has to re-do by hand. 2.0
answers them. Every module here ADDS metadata alongside the 1.x results; none
of them changes a detection, a correlation or a score. That separation is
deliberate and enforced by a regression gate -- the 1.x numbers in
docs/baseline_before_2.0.md must come out identical after every change here.

THE MODULES, IN THE ORDER AN ANALYST WORKS
------------------------------------------
    streams.py        Can I trust the data?    Which telemetry streams exist,
                      at what volume, over what period, from what file.
    blind_window.py   Was I blinded?           Did an actor disable logging,
                      and did data actually stop arriving?
    link_evidence.py  Why does this belong?    One plain sentence and the raw
                      log lines behind every link -- and every REJECTED link.
    gaps.py           What can't I see?        A ledger of absences, each with
                      the facts that justify it and the evidence to request.
    respond.py        What do I do now?        Indicators, whether it is still
                      happening, and recommended containment.

A DESIGN RULE THAT RUNS THROUGH ALL OF IT
-----------------------------------------
Never fabricate. Every gap, link reason and number shown must be computed from
the data. Where something cannot be determined, these modules emit UNKNOWN or
COVERAGE_UNKNOWN rather than a plausible guess -- because a confident wrong
answer costs an analyst more time than an honest "I don't know".

The sharpest case is absence. A missing log is NOT evidence of deletion. Logs
are missing for mundane reasons far more often than malicious ones: the agent
was never installed, the forwarder was down, the retention window rolled over.
2.0 only reports deletion or disablement when it holds a positive event proving
it -- an actual "logging disabled" admin record. Everything else is classified
NOT_COLLECTED or COVERAGE_UNKNOWN, which tells the analyst the truth: we cannot
see, and we do not know why.

PERSISTENCE
-----------
All output goes to new tables in the SAME DuckDB file, prefixed `cp2_`:

    cp2_stream_volume      cp2_links            cp2_gaps
    cp2_source_fingerprint cp2_rejected_links   cp2_indicators
    cp2_incident_separation

The 1.x `suspicious_events` table is read-only to this package. That means the
dashboard can read both, and rolling 2.0 back is dropping tables -- not a
restore.
"""

__version__ = "2.0.0"

CP2_TABLES = (
    "cp2_stream_volume",
    "cp2_source_fingerprint",
    "cp2_links",
    "cp2_rejected_links",
    "cp2_incident_separation",
    "cp2_gaps",
    "cp2_indicators",
)
