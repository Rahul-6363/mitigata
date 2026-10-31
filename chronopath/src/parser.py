"""
parser.py -- Stream a very large log file and pull out the suspicious events.

WHY THIS FILE EXISTS
--------------------
This is the component that makes the whole project possible on a laptop.

The problem: the data set is 15 GB. The demo machine has 16 GB of RAM. Loading
the logs into a Python list, a pandas DataFrame, or any in-memory structure will
exhaust memory and kill the process. That is the single biggest way this project
could fail.

The solution: never hold the logs. DuckDB reads the file in chunks straight from
disk, applies our filters *during* the scan, and hands back only the rows that
matched. 15 GB of logs collapses to a few thousand suspicious rows -- a few MB --
which everything downstream can then treat as small data.

MEASURED, NOT ASSUMED: this approach was benchmarked on the demo machine before
being adopted -- 360 MB scanned at ~1030 MB/s with peak RSS of 300 MB under a
hard 1 GB cap. Peak memory came in *below* the file size, which is only possible
if the data is genuinely being streamed. Run scripts/benchmark.py to reproduce.

SATISFIES
  FR-1  read the full data set without loading it into memory
  FR-2  detect suspicious events
  FR-3  map each detection to a MITRE ATT&CK technique and kill chain stage
  B-4   rules come from rules.yaml, so new detections need no code change
"""

import argparse
import os
import sys
import time

import duckdb
import yaml

# Run either as a script (python src/parser.py) or as an import (from the UI),
# so the module's own directory must be importable both ways.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ecs_adapter  # noqa: E402
import fortigate_adapter  # noqa: E402

# The log schema. Declaring it explicitly is a deliberate performance decision --
# see configure_connection() below for why this matters on a 15 GB file.
LOG_SCHEMA = {
    "timestamp": "VARCHAR",
    "host": "VARCHAR",
    "user": "VARCHAR",
    "event_id": "INTEGER",
    "src_ip": "VARCHAR",
    "dest_ip": "VARCHAR",
    "status": "VARCHAR",
    "process": "VARCHAR",
    "bytes_out": "BIGINT",
    "message": "VARCHAR",
}

DEFAULT_DB = "chronopath.db"


def detect_format(log_path):
    """
    Work out which of the three supported log formats this file is.

    Auto-detection rather than a mandatory flag, because the judges will point
    the tool at their own file and a wrong flag yields a baffling empty result
    instead of an obvious error. Each format has an unambiguous signature:

        fortigate  lines begin `date=` and contain `devname=` (the real
                   6.5 GB firex-10G.log)
        ecs        JSON with a nested "event" object or "@timestamp"
                   (edr_log_generator.py)
        flat       JSON with top-level "timestamp" and scalar "host"
                   (our own sample generator)

    Only the first handful of lines is read, so this is free even on 6.5 GB.
    """
    if fortigate_adapter.detect_fortigate(log_path):
        return "fortigate"
    return ecs_adapter.detect_format(log_path)


def load_rules(path="rules.yaml"):
    """Read detection rules from config. No detection logic lives in this file."""
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    rules = data.get("rules", [])
    if not rules:
        raise ValueError(f"No rules found in {path}")
    return rules


def configure_connection(con, memory_limit="8GB", spill_dir="./tmp_spill"):
    """
    Three settings that decide whether this survives 15 GB. Worth understanding
    individually, because they are the answer to "how does it not run out of RAM?"

    memory_limit
        A hard ceiling on what DuckDB may hold. We set 8 GB rather than 16 GB on
        purpose: the PRD's "Great" bar for peak memory is under 8 GB, and leaving
        headroom means the OS, Python and the browser still have room. If a query
        would exceed this, DuckDB spills instead of dying.

    temp_directory
        Where that spill goes. WITHOUT THIS, exceeding memory_limit is a fatal
        error rather than a slow query. This one line converts "crash on stage"
        into "finishes, slightly slower" -- cheap insurance.

    preserve_insertion_order = false
        By default DuckDB keeps output rows in input order, which forces it to
        buffer. Switching it off lets the engine emit results as it finds them
        and keeps memory flat across a huge scan. We do not care about input
        order because we sort by timestamp later anyway.
    """
    con.execute(f"SET memory_limit='{memory_limit}'")
    os.makedirs(spill_dir, exist_ok=True)
    con.execute(f"SET temp_directory='{spill_dir}'")
    con.execute("SET preserve_insertion_order=false")


def source_expr(log_path, log_format=None):
    """
    Build the DuckDB expression that reads the log file.

    We use read_ndjson with an EXPLICIT column schema rather than the more
    convenient read_json_auto, for two reasons that only bite at scale:

    1. Auto-detection samples the first N thousand rows to guess column types.
       On a 15 GB file, if a column looks like an integer for the first 20k rows
       and then contains a string at row 8 million, the whole scan fails. An
       explicit schema removes that entire failure mode.

    2. Sampling costs time and memory we do not need to spend -- we already know
       the shape of the data.

    Note the path is wrapped in single quotes and we reject quotes in the path,
    since this string is interpolated into SQL.

    FORMAT DISPATCH: the organisers' generator emits ECS (nested) JSON, while
    our own sample generator emits flat JSON. Rather than make the user pass a
    flag -- which produces a baffling empty result when set wrongly -- we sniff
    the first few lines and pick the reader. ECS files go through
    ecs_adapter, which renames the nested fields to the flat ones every rule
    already uses, inside the same streaming scan.
    """
    if "'" in log_path:
        raise ValueError("Log path may not contain a single quote.")

    if log_format is None:
        log_format = detect_format(log_path)
    if log_format == "fortigate":
        return fortigate_adapter.fortigate_source_expr(log_path)
    if log_format == "ecs":
        return ecs_adapter.ecs_source_expr(log_path)

    cols = ", ".join(f"{k}: '{v}'" for k, v in LOG_SCHEMA.items())
    return f"read_ndjson('{log_path}', columns={{{cols}}}, ignore_errors=true)"


# Statuses meaning the security control stopped the action. Such a detection is
# evidence of an attempt, not of a compromise.
PREVENTED_STATUSES = ("blocked", "dropped", "deny", "denied", "block", "reset")

OUTPUT_COLUMNS = ("timestamp, host, user, event_id, src_ip, dest_ip, status, "
                  "process, bytes_out, message, rule_name, mitre_technique, "
                  "mitre_name, kill_chain_stage, severity, event_count, outcome")


def outcome_sql(rule):
    """
    prevented  the control blocked it (status says so)
    attempted  the rule only shows an attempt, e.g. failed logins (`outcome:` in YAML)
    observed   the action went through
    """
    declared = escape(rule.get("outcome", "observed"))
    statuses = ", ".join(f"'{s}'" for s in PREVENTED_STATUSES)
    return (f"CASE WHEN lower(status) IN ({statuses}) THEN 'prevented' "
            f"ELSE '{declared}' END")


def label_columns(rule):
    """
    The ATT&CK columns for a rule: fixed literals, or a per-signature CASE.

    A single rule such as "IPS: Critical Exploit Attempt" covers Log4j,
    ZeroLogon and DNS zone transfers alike, which are different techniques in
    different kill chain stages. `technique_map` in the rule file maps each
    signature pattern to its own label; anything unmatched keeps the rule's
    default. Patterns are SQL LIKE expressions against `map_field`.
    """
    fields = {
        "mitre_technique": ("mitre_technique", lambda v: f"'{escape(v)}'"),
        "mitre_name": ("mitre_name", lambda v: f"'{escape(v)}'"),
        "kill_chain_stage": ("kill_chain_stage", lambda v: f"'{escape(v)}'"),
        "severity": ("severity", lambda v: str(int(v))),
    }
    mapping = rule.get("technique_map") or []
    column = rule.get("map_field", "message")
    out = []
    for alias, (key, fmt) in fields.items():
        default = fmt(rule[key])
        if not mapping:
            out.append(f"{default} AS {alias}")
            continue
        whens = []
        for entry in mapping:
            cond = " OR ".join(f"{column} LIKE '{escape(p)}'" for p in entry["match"])
            whens.append(f"WHEN {cond} THEN {fmt(entry.get(key, rule[key]))}")
        out.append(f"CASE {' '.join(whens)} ELSE {default} END AS {alias}")
    return ",\n            ".join(out)


def build_row_query(rule, src):
    """
    A 'row' rule: one log line is enough to be suspicious.

    The rule's SQL fragment goes into the WHERE clause, so DuckDB applies it
    while streaming. Rows that do not match are discarded as they are read and
    never accumulate anywhere.
    """
    return f"""
        SELECT
            timestamp, host, user, event_id, src_ip, dest_ip,
            status, process, bytes_out, message,
            '{escape(rule['name'])}'             AS rule_name,
            {label_columns(rule)},
            1                                    AS event_count,
            {outcome_sql(rule)}                  AS outcome
        FROM {src}
        WHERE {rule['sql_condition']}
    """


def build_aggregate_query(rule, src):
    """
    An 'aggregate' rule: suspicious only in bulk.

    One failed login is a typo; thirty is an attack. These rules GROUP BY a
    correlation key (usually host + user) and keep only groups passing a HAVING
    threshold.

    Memory note: a GROUP BY does need to hold one entry per distinct group. That
    is safe here because we group by host+user -- a few hundred machines times a
    few hundred users is a tiny hash table, regardless of whether the input is
    1 GB or 50 GB. Grouping by something high-cardinality (a timestamp, say)
    would be the one way to reintroduce a memory problem, which is why the
    correlation keys in rules.yaml are deliberately coarse.

    TIME BUCKETING: if a rule sets `bucket_minutes`, we also group by a fixed
    time window. This matters enormously for rate-based detections. Counting
    "failed logins per user" over a whole 15 GB file measures how forgetful
    someone is; counting them "per user per ten minutes" measures whether a
    machine is guessing passwords. Without bucketing, ordinary users accumulate
    more failures over days than an attacker generates in minutes -- a bug we hit
    and fixed, see the brute-force rule in rules.yaml.

    The bucket is computed with epoch arithmetic rather than a date function so
    it stays a cheap integer operation inside the streaming scan.

    We report MIN(timestamp) as the event time: the moment the burst began, which
    is what belongs on an attack timeline.

    THE BOUNDARY PROBLEM, and why this uses two overlapping passes:
    A naive fixed bucket splits a burst that straddles a boundary. Our attacker
    produced 35 failures over about four minutes that crossed a grid boundary,
    which a strict 10-minute grid splits into 18 + 17 -- both below a threshold
    of 20, so the real attack is
    MISSED while the false positives stay fixed. That is the worst possible
    trade.

    The fix is to evaluate two grids offset by half a window and keep the better
    count per group. Any burst shorter than half the window is fully inside at
    least one grid, so it can no longer be split in half by an unlucky start
    time. The cost is one extra aggregation over an already-filtered stream,
    which is negligible.
    """
    group_cols = ", ".join(rule["group_by"])

    bucket = rule.get("bucket_minutes")
    if not bucket:
        return _aggregate_sql(rule, src, group_cols, group_cols)

    seconds = int(bucket) * 60
    half = seconds // 2
    epoch = "epoch(CAST(timestamp AS TIMESTAMP))"
    # Grid A starts on the window; grid B is shifted by half a window.
    grid_a = f"CAST({epoch} / {seconds} AS BIGINT)"
    grid_b = f"CAST(({epoch} + {half}) / {seconds} AS BIGINT)"

    sql_a = _aggregate_sql(rule, src, f"{group_cols}, {grid_a}", group_cols)
    sql_b = _aggregate_sql(rule, src, f"{group_cols}, {grid_b}", group_cols)

    # DEDUPLICATION -- the subtlest part of this file. Two wrong approaches were
    # tried and measured before arriving at this one, so the reasoning is worth
    # recording.
    #
    # The two grids usually both flag the SAME burst, so duplicates must be
    # removed -- but genuinely separate attacks must survive.
    #
    #   ATTEMPT 1: PARTITION BY host, user.
    #     Wrong. Keeps one row per account for the whole data set, so an account
    #     brute-forced on Monday AND Friday reports once and the earlier attack
    #     vanishes. On 15 GB spanning weeks this hides most repeat attacks -- a
    #     false negative, the worst kind of bug.
    #
    #   ATTEMPT 2: PARTITION BY host, user, floor(start_time / window).
    #     Also wrong. A burst that straddles a window edge yields two start
    #     times that floor to DIFFERENT keys, so one burst is reported twice.
    #     Measured: failed at a 270-second offset.
    #
    #   THIS VERSION: merge by actual time proximity.
    #     Two detections for the same group describe the same burst if their
    #     start times are closer together than one window. LAG() compares each
    #     detection with the previous one for that group, and a row is kept only
    #     when it starts at least a full window after the one before it. This
    #     depends on elapsed time rather than where grid lines happen to fall,
    #     so it is correct at every offset.
    #
    # Dropping the lower-count duplicate is deliberate: between two readings of
    # one burst, the larger count is the more complete view of it.
    return f"""
        SELECT {OUTPUT_COLUMNS} FROM (
            SELECT *,
                   LAG(_start) OVER (
                       PARTITION BY {group_cols} ORDER BY _start
                   ) AS _prev_start
            FROM (
                SELECT *, epoch(CAST(timestamp AS TIMESTAMP)) AS _start,
                       ROW_NUMBER() OVER (
                           PARTITION BY {group_cols},
                                        CAST(epoch(CAST(timestamp AS TIMESTAMP))
                                             / {seconds} AS BIGINT)
                           ORDER BY event_count DESC
                       ) AS _rn
                FROM ( {sql_a} UNION ALL {sql_b} ) AS _grids
            ) AS _ranked
            WHERE _rn = 1
        ) AS _merged
        WHERE _prev_start IS NULL OR _start - _prev_start >= {seconds}
    """


def _aggregate_sql(rule, src, group_clause, group_cols):
    """
    Build one aggregate SELECT for a given grouping expression.

    `metric` lets a rule report something other than a row count. A brute-force
    rule wants "35 failed logons", but an exfiltration rule wants "1.2 GB sent"
    -- reporting "47 connections" there would bury the number that matters.
    Defaults to COUNT(*), which is right for most rules.
    """
    metric = rule.get("metric", "COUNT(*)")
    label = rule.get("metric_label",
                     "Bytes transferred" if "SUM(" in metric.upper()
                     else "Matching events")
    # Keep bytes_out meaningful when the metric is a byte total, so downstream
    # consumers (and the UI) can show the volume without re-deriving it.
    sum_bytes = metric if "bytes_out" in metric.lower() else "0"

    # ALWAYS emit the full standard column set, whatever the rule groups by.
    #
    # Earlier this spliced `{group_cols}` straight into the SELECT, which only
    # worked while every rule grouped by exactly host+user. The FortiGate rules
    # group by `src_ip` alone (brute force per attacking address) or `user`
    # alone (VPN credential reuse), and those rules failed to bind because the
    # output then had no `host` column for the table to accept.
    #
    # The fix: name host and user explicitly. A column that is part of the
    # grouping key passes through as itself; one that is not is collapsed with
    # MIN() so the row still carries a representative value. This keeps the
    # output schema fixed no matter how a rule chooses to aggregate.
    #
    # USER IS NOT COLLAPSED WITH MIN(). A brute-force rule grouped by src_ip
    # covers failures against many different accounts; MIN() picked an
    # arbitrary one ('002') and stamped it on 155 unrelated attacking IPs, which
    # the correlator then treated as one actor and merged into a single
    # incident. An account is only reported when the group really has one.
    grouped = {c.strip() for c in group_cols.split(",")}
    host_col = "host" if "host" in grouped else "MIN(host) AS host"
    user_col = ('"user"' if "user" in grouped else
                'CASE WHEN COUNT(DISTINCT "user") = 1 THEN MIN("user") '
                'ELSE \'-\' END AS "user"')
    src_col = "src_ip" if "src_ip" in grouped else "MIN(src_ip) AS src_ip"

    return f"""
        SELECT
            MIN(timestamp) AS timestamp,
            {host_col},
            {user_col},
            MAX(event_id)  AS event_id,
            {src_col},
            ''             AS dest_ip,
            'aggregated'   AS status,
            ''             AS process,
            {sum_bytes}    AS bytes_out,
            '{escape(label)}: ' || CAST({metric} AS VARCHAR) AS message,
            '{escape(rule['name'])}'             AS rule_name,
            '{escape(rule['mitre_technique'])}'  AS mitre_technique,
            '{escape(rule['mitre_name'])}'       AS mitre_name,
            '{escape(rule['kill_chain_stage'])}' AS kill_chain_stage,
            {int(rule['severity'])}              AS severity,
            {metric}                             AS event_count,
            '{escape(rule.get('outcome', 'observed'))}' AS outcome
        FROM {src}
        WHERE {rule['sql_condition']}
        GROUP BY {group_clause}
        HAVING {rule['having']}
    """


def escape(value):
    """Escape single quotes for SQL string literals (rule names, techniques)."""
    return str(value).replace("'", "''")


def run(log_path, rules_path=None, db_path=DEFAULT_DB,
        memory_limit="8GB", log_format=None):
    """
    Execute every rule against the log file and persist the hits.

    One rule = one streaming pass. We could fuse all rules into a single pass with
    a big OR, and that would be faster, but keeping them separate means a broken
    rule fails alone instead of taking the whole run down -- worth far more than
    speed during a hackathon, and the scan is not the bottleneck anyway.

    The rule file defaults to whichever matches the detected log format, because
    ECS logs expose different fields (threat.technique, event.category) than our
    flat format (event_id, bytes_out). Passing --rules overrides the choice.
    """
    if log_format is None:
        log_format = detect_format(log_path)
    if rules_path is None:
        rules_path = {"ecs": "rules_ecs.yaml",
                      "fortigate": "rules_fortigate.yaml"}.get(
                          log_format, "rules.yaml")

    rules = load_rules(rules_path)
    size_gb = os.path.getsize(log_path) / 1e9

    print(f"\nChronoPath parser")
    print(f"  input    {log_path}  ({size_gb:.2f} GB)")
    print(f"  format   {log_format.upper()}  (auto-detected)")
    print(f"  rules    {len(rules)} loaded from {rules_path}")
    print(f"  memory   capped at {memory_limit}, spilling to ./tmp_spill")
    print()

    # Delete any previous database so a re-run is clean and repeatable.
    if os.path.exists(db_path):
        os.remove(db_path)

    con = duckdb.connect(db_path)
    configure_connection(con, memory_limit=memory_limit)
    src = source_expr(log_path, log_format)

    con.execute("""
        CREATE TABLE suspicious_events (
            timestamp VARCHAR, host VARCHAR, user VARCHAR, event_id INTEGER,
            src_ip VARCHAR, dest_ip VARCHAR, status VARCHAR, process VARCHAR,
            bytes_out BIGINT, message VARCHAR, rule_name VARCHAR,
            mitre_technique VARCHAR, mitre_name VARCHAR,
            kill_chain_stage VARCHAR, severity INTEGER, event_count BIGINT,
            outcome VARCHAR
        )
    """)

    started = time.time()
    total = 0

    for rule in rules:
        t0 = time.time()
        if rule.get("type") == "aggregate":
            query = build_aggregate_query(rule, src)
        else:
            query = build_row_query(rule, src)

        try:
            con.execute(f"INSERT INTO suspicious_events {query}")
            hits = con.execute(
                "SELECT COUNT(*) FROM suspicious_events WHERE rule_name = ?",
                [rule["name"]],
            ).fetchone()[0]
            total += hits
            print(f"  [{rule['mitre_technique']:<10}] {rule['name'][:44]:<44} "
                  f"{hits:>6} hits   {time.time() - t0:5.1f}s")
        except Exception as exc:
            # A bad rule must not kill the run -- report it and carry on.
            print(f"  [SKIPPED  ] {rule['name'][:44]:<44} rule failed: {exc}")

    elapsed = time.time() - started

    # An index on the correlation columns. The graph engine filters on these
    # constantly, and this is what keeps opening an incident under the PRD's
    # 500 ms "Great" target.
    con.execute("CREATE INDEX idx_host ON suspicious_events(host)")
    con.execute("CREATE INDEX idx_user ON suspicious_events(user)")
    con.close()

    throughput = size_gb * 1000 / elapsed if elapsed > 0 else 0
    print()
    print(f"  {total} suspicious events written to {db_path}")
    print(f"  scanned {size_gb:.2f} GB in {elapsed:.1f}s  (~{throughput:.0f} MB/s)")
    if size_gb > 0:
        reduction = (size_gb * 1e9) / max(total, 1)
        print(f"  reduction: ~{reduction/1e6:.1f} MB of logs per suspicious event")
    print()
    return total


def main():
    ap = argparse.ArgumentParser(
        description="Stream security logs and extract MITRE-tagged suspicious events.")
    ap.add_argument("--input", default="data/sample.ndjson", help="NDJSON log file")
    ap.add_argument("--rules", default=None,
                    help="Rule file (default: auto-chosen from the log format)")
    ap.add_argument("--format", choices=["ecs", "flat", "fortigate"],
                    default=None,
                    help="Force a log format instead of auto-detecting")
    ap.add_argument("--db", default=DEFAULT_DB)
    ap.add_argument("--memory-limit", default="8GB",
                    help="DuckDB memory ceiling (PRD 'Great' bar is under 8GB)")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        raise SystemExit(
            f"Log file not found: {args.input}\n"
            f"Generate one first:  python scripts/generate_sample.py")

    run(args.input, args.rules, args.db, args.memory_limit, args.format)


if __name__ == "__main__":
    main()
