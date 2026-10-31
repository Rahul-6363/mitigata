"""
streams.py -- Telemetry streams and source provenance (ChronoPath 2.0, Task 1).

WHY THIS FILE EXISTS
--------------------
The first question a competent analyst asks about any finding is not "what did
you detect?" but "can I trust the data you detected it in?" Without an answer,
every conclusion downstream is unfalsifiable. Two specific failures are routine:

  1. "There is no endpoint activity for that server."
     Meaning A: nothing happened there.          (reassuring)
     Meaning B: that server never sent us logs.  (alarming)
     Identical silence. Opposite responses. Only coverage data separates them.

  2. "The attack started at 03:55."
     Or the file simply begins at 03:55 and the attack started days earlier.

This module makes both answerable from the data, by recording what arrived.

A FORTIGATE LOG IS NOT ONE SOURCE -- THAT IS THE KEY INSIGHT
------------------------------------------------------------
It looks like one file, so the naive reading is "we have one telemetry source,
nothing to compare". In fact FortiGate multiplexes independent subsystems into
one syslog stream, each with its own coverage, and the `type`/`subtype` pair
names them. Measured on the real file (first 300,000 lines, 12 streams):

    traffic/forward     64.0%   firewall allow/deny with byte counts
    event/system        15.7%   admin logins, config changes
    utm/webfilter        4.5%   URL filtering
    utm/ips              3.1%   named exploit detections
    utm/dns              3.0%   DNS lookups
    utm/app-ctrl         3.0%   application control
    utm/virus            1.5%   antivirus
    event/vpn            1.5%   SSL-VPN tunnels
    event/{ha,connector,sdwan,dhcp}  3.6%

So a real coverage view is possible from a single supplied file: if
`event/system` goes quiet for two hours while `traffic/forward` keeps flowing,
that is a per-stream outage visible in this data -- the comparison Task 2 needs.

THE TIME TRAP, AND WHY THE FINGERPRINT RECORDS IT
-------------------------------------------------
Every line in the organisers' file carries TWO clocks plus a timezone:

    date=2026-10-23 time=08:48:26 eventtime=1792745306000000000 tz="+0530"

Measured: decoding `eventtime` as UTC yields exactly 08:48:26, matching the
`date`/`time` pair. Decoding it as +0530 yields 14:18:26 -- a 5.5-hour error.
So the wall-clock fields are effectively UTC and the `tz` tag does NOT describe
them.

A 5.5-hour shift would be catastrophic and silent: it would not crash anything,
it would just move the attack to the wrong day and break every correlation
against another source. Our pipeline uses `date`/`time`, which is internally
consistent and agrees with `eventtime`-as-UTC. This module records that choice
in the fingerprint so the decision is auditable instead of buried in a regex.

MEMORY DISCIPLINE
-----------------
Two places here could trivially blow a 16 GB laptop and neither does:

  * The SHA-256 is read in 8 MB chunks, so hashing 6.54 GB costs 8 MB of RAM.
    Reading the file whole to hash it would need 6.54 GB.
  * Stream volume is aggregated by DuckDB in a streaming GROUP BY, so only the
    result (hundreds of rows) is ever materialised.
"""

import hashlib
import os
import re
from datetime import datetime, timezone

# Read the file in 8 MB slices when hashing. Large enough that syscall overhead
# is irrelevant on a 6.5 GB file, small enough to be invisible in RAM.
HASH_CHUNK_BYTES = 8 * 1024 * 1024

# How many lines to sample when measuring stream shape and timestamp health.
# The streams are well-mixed (interleaved by arrival, not sorted by type), so a
# head sample is representative. Kept small because this runs on every ingest.
PROBE_LINES = 200_000

_DATE_RE = re.compile(r"date=(\S+)")
_TIME_RE = re.compile(r"time=(\S+)")
_EVENTTIME_RE = re.compile(r"eventtime=(\d+)")
_TZ_RE = re.compile(r'tz="([^"]*)"')
_TYPE_RE = re.compile(r'type="([^"]*)"')
_SUBTYPE_RE = re.compile(r'subtype="([^"]*)"')


def sha256_streaming(path, chunk_bytes=HASH_CHUNK_BYTES):
    """
    Hash a file without loading it.

    WHY A HASH AT ALL: provenance. A finding that cites "firex-10G.log" is not
    reproducible, because that name says nothing about content -- any file can
    be called that. A digest pins the exact bytes the conclusions came from, so
    a reviewer can confirm they are looking at the same evidence. That is the
    difference between a claim and a verifiable claim.
    """
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def _probe_fortigate(path, probe_lines=PROBE_LINES):
    """
    Sample the head of a FortiGate file for stream shape and clock health.

    Returns counts per (type, subtype), how many lines carried a usable
    timestamp, and what the two clocks say about each other.
    """
    streams = {}
    seen = parsed_ts = bad_ts = 0
    timezones = set()
    clock_agree = clock_disagree = 0
    eventtime_present = 0

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if seen >= probe_lines:
                break
            if not line.strip():
                continue
            seen += 1

            t = _TYPE_RE.search(line)
            s = _SUBTYPE_RE.search(line)
            key = (t.group(1) if t else "unknown",
                   s.group(1) if s else "unknown")
            streams[key] = streams.get(key, 0) + 1

            d, tm = _DATE_RE.search(line), _TIME_RE.search(line)
            if d and tm:
                parsed_ts += 1
            else:
                bad_ts += 1

            tz = _TZ_RE.search(line)
            if tz:
                timezones.add(tz.group(1))

            # Cross-check the two clocks on the same line. This is the only way
            # to establish which interpretation of eventtime is correct, and it
            # has to be measured rather than assumed -- see the module notes.
            et = _EVENTTIME_RE.search(line)
            if et and d and tm:
                eventtime_present += 1
                try:
                    as_utc = datetime.fromtimestamp(
                        int(et.group(1)) / 1e9, timezone.utc)
                    wall = f"{d.group(1)}T{tm.group(1)}"
                    if as_utc.strftime("%Y-%m-%dT%H:%M:%S") == wall:
                        clock_agree += 1
                    else:
                        clock_disagree += 1
                except (ValueError, OSError, OverflowError):
                    pass

    return {
        "streams": streams,
        "probed_lines": seen,
        "probe_parsed_ts": parsed_ts,
        "probe_bad_ts": bad_ts,
        "timezones": sorted(timezones),
        "eventtime_present": eventtime_present,
        "clock_agree_utc": clock_agree,
        "clock_disagree_utc": clock_disagree,
    }


def _clock_note(probe):
    """
    Turn the measured clock comparison into a sentence an analyst can act on.

    Deliberately states what WAS measured, not a rule of thumb. If the two
    clocks disagree we say so plainly rather than silently preferring one.
    """
    if not probe.get("eventtime_present"):
        return ("Single clock: the date/time pair only. No eventtime field "
                "present, so no cross-check was possible.")

    tzs = probe.get("timezones") or []
    tz_txt = ", ".join(tzs) if tzs else "none"
    agree, disagree = probe["clock_agree_utc"], probe["clock_disagree_utc"]

    if agree and not disagree:
        return (
            f"Two clocks present (date/time and eventtime); tz tag reads "
            f"{tz_txt}. Measured on {agree} lines: eventtime decoded as UTC "
            f"matches the date/time pair exactly, so the wall-clock fields are "
            f"effectively UTC and the tz tag does not apply to them. "
            f"The pipeline uses date/time. Reading eventtime as {tz_txt} "
            f"instead would shift every event and corrupt correlation."
        )
    if disagree and not agree:
        return (
            f"Two clocks present and they DISAGREE on all {disagree} lines "
            f"checked (tz tag {tz_txt}). The pipeline uses the date/time pair. "
            f"Treat cross-source correlation as unreliable until the offset is "
            f"established."
        )
    return (
        f"Two clocks present; mixed agreement ({agree} agree, {disagree} "
        f"disagree, tz tag {tz_txt}). The pipeline uses the date/time pair. "
        f"Mixed agreement suggests more than one sending device or a clock "
        f"change mid-capture."
    )


def _ensure_tables(con):
    """
    Create the 2.0 stream tables if absent.

    Separate CREATE statements rather than one schema migration, because this
    package must be safe to run against a 1.x database that has never seen it:
    adding tables can never damage `suspicious_events`.
    """
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_stream_volume (
            source       VARCHAR,
            stream       VARCHAR,
            hour_bucket  TIMESTAMP,
            event_count  BIGINT
        )
    """)
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_source_fingerprint (
            source           VARCHAR,
            path             VARCHAR,
            sha256           VARCHAR,
            size_bytes       BIGINT,
            detected_format  VARCHAR,
            earliest_ts      VARCHAR,
            latest_ts        VARCHAR,
            total_rows       BIGINT,
            parsed_rows      BIGINT,
            rejected_rows    BIGINT,
            bad_timestamp_rows BIGINT,
            timestamp_field  VARCHAR,
            clock_note       VARCHAR,
            streams_found    INTEGER,
            recorded_at      TIMESTAMP
        )
    """)


def build_stream_volume(con, source_expr, source_name, log_format):
    """
    Fill `cp2_stream_volume`: events per stream per hour, over the whole file.

    WHY HOURLY: it is the coarsest bucket that still shows a logging outage.
    Task 2 compares a blind window against the window before it, and the real
    INC-02 window is about two hours -- daily buckets would hide it entirely,
    while per-minute buckets on a 6-day file would produce ~8,600 rows per
    stream and show noise rather than shape.

    WHY THIS IS CHEAP: it is a streaming GROUP BY. DuckDB scans the file once,
    keeps one counter per (stream, hour) -- a few hundred live values -- and
    discards every row as it goes. Nothing is materialised, so peak memory is
    the scan buffer, not the data.

    `source_expr` is the same adapter sub-select the detection rules read, so
    the streams reported here are exactly the ones the rules saw. Reading the
    file a second way would risk reporting coverage for data the detector never
    actually used.
    """
    _ensure_tables(con)

    if log_format == "fortigate":
        # The stream identity, as confirmed from the data: type/subtype.
        stream_sql = """
            CASE WHEN fg_type = '' THEN 'unknown' ELSE fg_type END
            || '/' ||
            CASE WHEN fg_subtype = '' THEN 'unknown' ELSE fg_subtype END
        """
    else:
        # The other two formats carry no equivalent subsystem field. Rather
        # than invent one, every row is one stream named for the format. That
        # is honest: for ECS and flat JSON we genuinely cannot break coverage
        # down further, and pretending otherwise would be fabricated detail.
        stream_sql = f"'{log_format}'"

    con.execute("DELETE FROM cp2_stream_volume WHERE source = ?", [source_name])
    con.execute(f"""
        INSERT INTO cp2_stream_volume
        SELECT ? AS source,
               {stream_sql} AS stream,
               date_trunc('hour', TRY_CAST(timestamp AS TIMESTAMP)) AS hour_bucket,
               COUNT(*) AS event_count
        FROM {source_expr}
        WHERE TRY_CAST(timestamp AS TIMESTAMP) IS NOT NULL
        GROUP BY 1, 2, 3
    """, [source_name])

    return con.execute(
        "SELECT COUNT(*), COUNT(DISTINCT stream), MIN(hour_bucket), "
        "MAX(hour_bucket), SUM(event_count) "
        "FROM cp2_stream_volume WHERE source = ?", [source_name]).fetchone()


def build_fingerprint(con, log_path, source_name, log_format,
                      total_rows=None, parsed_rows=None, rejected_rows=None):
    """
    Record provenance for one input file.

    `rejected_rows` is the count the reader could not use at all. It feeds a
    PARSE_FAILURE gap in Task 4, which is the honest way to handle unreadable
    data: an analyst told "we processed 9,125,382 of 9,125,400 rows" knows the
    18 missing ones might matter. An analyst told nothing assumes completeness.
    """
    _ensure_tables(con)

    sha, size = sha256_streaming(log_path)

    if log_format == "fortigate":
        probe = _probe_fortigate(log_path)
        ts_field = "date + time (FortiGate wall clock)"
    else:
        probe = {"streams": {}, "probed_lines": 0, "probe_parsed_ts": 0,
                 "probe_bad_ts": 0, "timezones": [], "eventtime_present": 0,
                 "clock_agree_utc": 0, "clock_disagree_utc": 0}
        ts_field = ("@timestamp (ECS, ISO-8601)" if log_format == "ecs"
                    else "timestamp (ISO-8601)")

    rng = con.execute(
        "SELECT MIN(hour_bucket), MAX(hour_bucket), SUM(event_count) "
        "FROM cp2_stream_volume WHERE source = ?", [source_name]).fetchone()
    earliest, latest, volume_rows = rng if rng else (None, None, None)

    if total_rows is None:
        total_rows = int(volume_rows or 0)
    if parsed_rows is None:
        parsed_rows = int(volume_rows or 0)

    # Rows the scan read but whose timestamp could not be cast. These are not
    # dropped silently: Task 4 raises a PARSE_FAILURE gap, and the timeline
    # flags them rather than sorting them to the epoch.
    if rejected_rows is None:
        rejected_rows = max(0, int(total_rows) - int(parsed_rows))
    bad_ts = max(0, int(total_rows) - int(volume_rows or 0))

    streams_found = con.execute(
        "SELECT COUNT(DISTINCT stream) FROM cp2_stream_volume WHERE source = ?",
        [source_name]).fetchone()[0]

    con.execute("DELETE FROM cp2_source_fingerprint WHERE source = ?",
                [source_name])
    con.execute("""
        INSERT INTO cp2_source_fingerprint VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, [
        source_name, os.path.abspath(log_path), sha, size, log_format,
        str(earliest) if earliest else None,
        str(latest) if latest else None,
        int(total_rows), int(parsed_rows), int(rejected_rows), int(bad_ts),
        ts_field, _clock_note(probe), int(streams_found or 0),
        datetime.now(),
    ])

    return {
        "source": source_name, "sha256": sha, "size_bytes": size,
        "format": log_format, "earliest": earliest, "latest": latest,
        "total_rows": total_rows, "rejected_rows": rejected_rows,
        "bad_timestamp_rows": bad_ts, "streams": streams_found,
        "clock_note": _clock_note(probe), "probe": probe,
    }


def record_source(con, log_path, source_name, log_format, source_expr,
                  total_rows=None, parsed_rows=None):
    """
    One call to do both halves of Task 1 for a file: volume, then fingerprint.

    Order matters -- the fingerprint reads the volume table for the file's time
    range, so volume must exist first.
    """
    _ensure_tables(con)
    vol = build_stream_volume(con, source_expr, source_name, log_format)
    fp = build_fingerprint(con, log_path, source_name, log_format,
                           total_rows=total_rows, parsed_rows=parsed_rows)
    fp["volume_rows"] = vol[0] if vol else 0
    return fp


def get_fingerprints(con):
    """Read back every recorded source, for the dashboard's Sources tab."""
    try:
        rows = con.execute(
            "SELECT * FROM cp2_source_fingerprint ORDER BY recorded_at"
        ).fetchall()
        cols = [d[0] for d in con.description]
    except Exception:
        return []
    return [dict(zip(cols, r)) for r in rows]


def stream_summary(con, source=None):
    """
    Per-stream totals and time span, for the coverage view.

    Returns the share of all events each stream carries, which is what makes a
    coverage table readable: "event/system is 15.7% of traffic" tells an
    analyst whether a drop in it would be noticeable.
    """
    try:
        where, params = "", []
        if source:
            where, params = "WHERE source = ?", [source]
        rows = con.execute(f"""
            SELECT stream,
                   SUM(event_count) AS events,
                   MIN(hour_bucket) AS first_hour,
                   MAX(hour_bucket) AS last_hour,
                   COUNT(*) AS active_hours
            FROM cp2_stream_volume {where}
            GROUP BY stream ORDER BY events DESC
        """, params).fetchall()
    except Exception:
        return []
    total = sum(r[1] for r in rows) or 1
    return [{
        "stream": r[0], "events": int(r[1]),
        "share_pct": round(r[1] / total * 100, 2),
        "first_hour": r[2], "last_hour": r[3], "active_hours": int(r[4]),
    } for r in rows]
