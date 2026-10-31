"""
applog_adapter.py -- Read plain-text application logs (`sample1.log`).

WHY THIS FILE EXISTS
--------------------
`sample1.log` is a fourth format: one event per line, a timestamp, a level, a
component tag, then unquoted `key=value` pairs with an optional quoted `msg`.

    2026-10-30 08:49:04 CRIT [iam] event_id=1011 src_ip=185.220.101.44
    user=admin action=admin_account_created target_user=svc_updater ...

It is neither JSON nor FortiGate syslog (no `date=`/`devname=`), so none of the
existing readers matched it and the parser fell through to the flat JSON reader,
which silently returns nothing. As with `fortigate_adapter.py`, this maps the
fields onto the flat column names the engine uses; detection, correlation, graph
and UI code are untouched.

It reads the same way as the FortiGate adapter -- each line as one text column,
fields pulled out with `regexp_extract` inside the streaming scan -- so it scales
to large files without loading them.

FIELD MAPPING
    date + time       -> timestamp   (ISO 8601)
    src_ip            -> src_ip
    user              -> user
    event_id          -> event_id
    status            -> status
    action            -> process     (nearest equivalent: what was done)
    bytes             -> bytes_out
    msg / action      -> message
    ... plus app_* columns used by rules_applog.yaml

A NOTE ON "host": these lines name no machine; they are all written by one
application. `host` is therefore a constant, `app-server`. That is harmless for
correlation: the engine drops any entity shared by more than a few accounts as
infrastructure, exactly as it does for the firewall's management IP.
"""

APP_HOST = "app-server"

# Keys are matched only at the start of the line or after a space, so `user=`
# does not also match inside `target_user=`.
FIELD_PATTERNS = {
    # --- the fixed prefix: date, time, level, [component] ---
    "app_date":       r"^(\d{4}-\d{2}-\d{2}) ",
    "app_time":       r"^\S+ (\d{2}:\d{2}:\d{2}) ",
    "app_level":      r"^\S+ \S+ ([A-Z]+) ",
    "app_component":  r"^\S+ \S+ \S+ \[([^\]]*)\]",

    # --- key=value pairs ---
    "app_event_id":   r"(?:^| )event_id=(\d+)",
    "src_ip":         r"(?:^| )src_ip=(\S+)",
    "user":           r"(?:^| )user=(\S+)",
    "app_action":     r"(?:^| )action=(\S+)",
    "status":         r"(?:^| )status=(\S+)",
    "app_reason":     r"(?:^| )reason=(\S+)",
    "app_target_user": r"(?:^| )target_user=(\S+)",
    "app_target":     r"(?:^| )target=(\S+)",
    "app_role":       r"(?:^| )role=(\S+)",
    "app_change":     r"(?:^| )change=(\S+)",
    "app_session":    r"(?:^| )session_id=(\S+)",
    "app_bytes":      r"(?:^| )bytes=(\d+)",
    "app_msg":        r'(?:^| )msg="([^"]*)"',
}


def _esc(pattern):
    """Escape a regex for embedding in a single-quoted SQL string literal."""
    return pattern.replace("'", "''")


def applog_source_expr(log_path):
    """
    Build SQL that reads the application log and presents flat column names.

    Returned as a sub-select so every rule's WHERE clause works unchanged.
    """
    if "'" in log_path:
        raise ValueError("Log path may not contain a single quote.")

    def col(name, pattern):
        return f"regexp_extract(line, '{_esc(pattern)}', 1) AS {name}"

    extracted = [col(n, p) for n, p in FIELD_PATTERNS.items()]

    # Same reader settings as fortigate_adapter.py, for the same reasons: one
    # whole line per row, no CSV quote handling, tolerate malformed lines.
    reader = (
        f"read_csv('{log_path}', delim='\\x07', header=false, "
        f"columns={{'line': 'VARCHAR'}}, ignore_errors=true, "
        f"quote='', escape='', strict_mode=false)"
    )

    return f"""(
        SELECT
            app_date || 'T' || app_time            AS timestamp,
            '{APP_HOST}'                           AS host,
            CASE WHEN "user" <> '' THEN "user" ELSE '-' END      AS "user",
            TRY_CAST(app_event_id AS INTEGER)      AS event_id,
            src_ip,
            ''                                     AS dest_ip,
            status,
            app_action                             AS process,
            TRY_CAST(app_bytes AS BIGINT)          AS bytes_out,
            CASE WHEN app_msg <> '' THEN app_msg ELSE app_action END AS message,
            app_level, app_component, app_action, app_reason,
            app_target_user, app_target, app_role, app_change, app_session
        FROM (
            SELECT {', '.join(extracted)}
            FROM {reader}
        )
        WHERE app_date <> '' AND app_time <> ''
    )"""


def detect_applog(log_path, sample_lines=20):
    """
    Decide whether a file is this application-log format.

    A line starts `YYYY-MM-DD HH:MM:SS LEVEL [component]` and carries
    `action=`. Only the first few lines are read.
    """
    import re
    signature = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [A-Z]+ \[[^\]]*\] ")
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(sample_lines):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                if signature.match(line) and "action=" in line:
                    return True
                # JSON or FortiGate means one of the other formats.
                if line.startswith("{") or line.startswith("date="):
                    return False
    except OSError:
        pass
    return False
