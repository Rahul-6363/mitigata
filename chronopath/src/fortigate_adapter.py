"""
fortigate_adapter.py -- Read the organisers' FortiGate firewall logs.

WHY THIS FILE EXISTS
--------------------
The real data set (`firex-10G.log`, 6.5 GB) is **FortiGate syslog**: flat
`key=value` text, one event per line. Not JSON at all.

    date=2026-10-23 time=08:48:26 type="event" subtype="system"
    logdesc="Admin login failed" user="admin" srcip=209.50.167.232
    dstip=10.10.99.1 action="login" status="failed" ...

That is a third format, after our own flat JSON and the ECS JSON from
`edr_log_generator.py`. Rather than fork the engine again, this adapter maps
FortiGate fields onto the same flat column names every rule already uses --
exactly as `ecs_adapter.py` does for ECS. The detection, correlation, graph and
UI code is untouched.

HOW IT READS A NON-JSON FORMAT AT SPEED
---------------------------------------
DuckDB has no `key=value` reader, so we read each line as a single text column
and pull fields out with `regexp_extract` inside the same streaming scan. That
sounds slow; measured, it is not:

    1,583 MB scanned in 1.1 s  =  1,440 MB/s,  peak RSS 422 MB

At that rate the full 6.5 GB file is about 5 seconds of scan time. Memory stays
flat because nothing is materialised -- the regexes run per row as the line is
read and discarded.

The delimiter is set to \\x07 (a control character that cannot occur in syslog
text) so the CSV reader never splits a line on a comma or quote. `quote=''` and
`escape=''` switch off CSV quote handling entirely, which matters because these
lines are full of `"` characters that are not CSV quoting.

WHAT THE DATA CONTAINS (measured on a 200k-line sample)
-------------------------------------------------------
    traffic/forward     64%   firewall allow/deny, with byte counts
    event/system        16%   admin logins -- 27,885 FAILED in the sample
    utm/webfilter        4.5% URL filtering
    utm/ips              3%   named exploit detections (Log4j, ZeroLogon, ...)
    utm/dns              3%   DNS lookups
    utm/app-ctrl         3%   application control
    utm/virus            1.5% malware detections
    plus vpn, ha, dhcp, sdwan, connector events

FIELD MAPPING
    date + time            -> timestamp   (ISO 8601, built by concatenation)
    srcip                  -> src_ip
    dstip                  -> dest_ip     and -> host (see note below)
    user                   -> user
    action                 -> status
    service / app          -> process     (nearest equivalent)
    sentbyte               -> bytes_out
    attack / logdesc / msg -> message
    ... plus FortiGate-only columns used by rules_fortigate.yaml

A NOTE ON "host": FortiGate logs identify machines by IP, not hostname. `host`
is always our own asset: the DESTINATION for inbound traffic (the machine being
attacked) and the internal SOURCE for outbound traffic (the machine that sent
it). `src_ip`/`dest_ip` keep the raw direction.
"""

# Every field we pull out of a line, with the regex that extracts it.
#
# Two shapes of value exist in this format and both must be handled:
#   quoted:    type="event"      -> ([^"]*) inside quotes
#   unquoted:  srcip=10.0.0.1    -> (\S+) up to the next space
# Getting this wrong silently yields empty columns, so each entry below is
# written for the shape that field actually uses in the real file.
FIELD_PATTERNS = {
    # --- core identity and timing ---
    "fg_date":      r"date=(\S+)",
    "fg_time":      r"time=(\S+)",
    "src_ip":       r"srcip=(\S+)",
    "dest_ip":      r"dstip=(\S+)",
    "user":         r'user="([^"]*)"',

    # --- classification ---
    "fg_type":      r'type="([^"]*)"',
    "fg_subtype":   r'subtype="([^"]*)"',
    "fg_level":     r'level="([^"]*)"',
    "status":       r'action="([^"]*)"',
    "fg_status":    r'status="([^"]*)"',
    "fg_logdesc":   r'logdesc="([^"]*)"',
    "fg_reason":    r'reason="([^"]*)"',

    # --- threat detail ---
    "fg_attack":    r'attack="([^"]*)"',
    "fg_severity":  r'severity="([^"]*)"',
    "fg_virus":     r'virus="([^"]*)"',
    "fg_app":       r'app="([^"]*)"',
    "fg_apprisk":   r'apprisk="([^"]*)"',
    "fg_service":   r'service="([^"]*)"',
    "fg_hostname":  r'hostname="([^"]*)"',
    "fg_url":       r'url="([^"]*)"',
    "fg_catdesc":   r'catdesc="([^"]*)"',
    "fg_msg":       r'msg="([^"]*)"',

    # --- network context ---
    "fg_srcintfrole": r'srcintfrole="([^"]*)"',
    "fg_dstintfrole": r'dstintfrole="([^"]*)"',
    "fg_srccountry":  r'srccountry="([^"]*)"',
    "fg_dstcountry":  r'dstcountry="([^"]*)"',
    "fg_dstport":     r"dstport=(\d+)",
}


def _esc(pattern):
    """Escape a regex for embedding in a single-quoted SQL string literal."""
    return pattern.replace("'", "''")


def fortigate_source_expr(log_path):
    """
    Build SQL that reads FortiGate syslog and presents flat column names.

    Returned as a sub-select so callers treat it like a table and every rule's
    WHERE clause works unchanged.

    The timestamp is assembled as `date || 'T' || time`, which yields ISO 8601
    ('2026-10-23T08:48:26'). That matters downstream: the correlation engine
    parses timestamps with datetime.fromisoformat(), and the aggregate rules
    cast them to TIMESTAMP for time bucketing. Both need this exact shape.
    """
    if "'" in log_path:
        raise ValueError("Log path may not contain a single quote.")

    def col(name, pattern):
        return f"regexp_extract(line, '{_esc(pattern)}', 1) AS {name}"

    extracted = [col(n, p) for n, p in FIELD_PATTERNS.items()]

    # strict_mode=false is REQUIRED on the real file, and the reason is worth
    # recording. A 200k-line sample parsed fine; the full 6.5 GB file failed at
    # about 63% with "CSV Parser state machine reached an invalid state".
    # Real syslog contains lines with stray quotes, embedded control characters
    # and other things no CSV standard anticipates. Strict mode aborts the
    # whole scan on the first such line; relaxed mode reads it as text, which
    # is all we want since we extract fields by regex anyway.
    #
    # This is the single setting that decides whether the tool works on the
    # real data set at all -- a sample-only test would never have found it.
    reader = (
        f"read_csv('{log_path}', delim='\\x07', header=false, "
        f"columns={{'line': 'VARCHAR'}}, ignore_errors=true, "
        f"quote='', escape='', strict_mode=false)"
    )

    return f"""(
        SELECT
            -- Rebuild an ISO-8601 timestamp from FortiGate's split fields.
            CASE WHEN fg_date <> '' AND fg_time <> ''
                 THEN fg_date || 'T' || fg_time
                 ELSE '' END                       AS timestamp,
            -- FortiGate identifies machines by IP. `host` is OUR asset: the
            -- destination for inbound traffic, but the internal source for
            -- outbound traffic. 99.7% of IPS hits run LAN/DMZ -> internet;
            -- using dstip there named an internet address as the victim.
            CASE WHEN fg_srcintfrole IN ('lan', 'dmz')
                      AND fg_dstintfrole = 'wan' THEN src_ip
                 WHEN dest_ip <> '' THEN dest_ip
                 ELSE src_ip END                   AS host,
            CASE WHEN "user" <> '' THEN "user" ELSE '-' END      AS "user",
            0                                      AS event_id,
            src_ip, dest_ip,
            status,
            -- Nearest equivalent of a process name: the app or service.
            CASE WHEN fg_app <> '' THEN fg_app ELSE fg_service END AS process,
            TRY_CAST(fg_sentbyte AS BIGINT)        AS bytes_out,
            -- The most descriptive text available for this line.
            CASE WHEN fg_attack  <> '' THEN fg_attack
                 WHEN fg_virus   <> '' THEN fg_virus
                 WHEN fg_logdesc <> '' THEN fg_logdesc
                 WHEN fg_msg     <> '' THEN fg_msg
                 ELSE fg_subtype END               AS message,
            fg_type, fg_subtype, fg_level, fg_status, fg_logdesc, fg_reason,
            fg_attack, fg_severity, fg_virus, fg_app, fg_apprisk, fg_service,
            fg_hostname, fg_url, fg_catdesc, fg_msg,
            fg_srcintfrole, fg_dstintfrole, fg_srccountry, fg_dstcountry,
            TRY_CAST(fg_dstport AS INTEGER)        AS fg_dstport
        FROM (
            SELECT
                {', '.join(extracted)},
                regexp_extract(line, 'sentbyte=(\\d+)', 1) AS fg_sentbyte
            FROM {reader}
        )
        WHERE fg_date <> ''
    )"""


def detect_fortigate(log_path, sample_lines=20):
    """
    Decide whether a file is FortiGate syslog.

    FortiGate lines are unmistakable: they start with `date=` and carry
    `devname=` plus `type=`. Checking a handful of lines is enough, and costs
    nothing even on a 6.5 GB file because we stop after the first few.
    """
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(sample_lines):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                if line.startswith("date=") and "devname=" in line \
                        and "type=" in line:
                    return True
                # A JSON line means this is one of the other formats.
                if line.startswith("{"):
                    return False
    except OSError:
        pass
    return False
