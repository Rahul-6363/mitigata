"""
ecs_adapter.py -- Read the organiser's EDR logs (ECS format) as if they were flat.

WHY THIS FILE EXISTS
--------------------
The organisers supplied `edr_log_generator.py`, which emits **ECS** (Elastic
Common Schema) JSON. That is a very different shape from the flat records the
rest of ChronoPath was first built against:

    OUR ORIGINAL FLAT SHAPE          THE ORGANISERS' ECS SHAPE
    {"host": "HR-07",                {"host": {"name": "WS-FIN-012", ...},
     "user": "bob",                   "user": {"name": "rkumar"},
     "event_id": 4625,                "event": {"kind":"alert","category":["authentication"]},
     "bytes_out": 500}                "threat": {"technique": {"id": ["T1110"]}},
                                      "network": {"bytes": 4096}}

Rather than rewrite the detection engine, the graph engine and every rule, this
module translates ECS into the flat column names everything already expects.
One adapter, written once, and the other 1,500 lines keep working unchanged.

THIS IS THE RIGHT CALL, not a shortcut. A log pipeline that only accepts one
vendor's field names is a toy. Real SIEMs put a normalisation layer exactly
here, because the field names change with every data source while the detection
logic should not.

HOW THE MAPPING WORKS
---------------------
DuckDB can read nested JSON natively, so the translation is pure SQL executed
*during* the streaming scan. Nothing is materialised, so the memory story in
parser.py is unchanged.

    ECS path                           -> our flat column
    @timestamp                         -> timestamp
    host.name                          -> host
    user.name                          -> user
    winlog.event_id                    -> event_id
    source.ip                          -> src_ip
    destination.ip                     -> dest_ip
    event.outcome                      -> status
    process.name                       -> process
    network.bytes                      -> bytes_out
    threat.technique.id[1]             -> ecs_technique   (pre-tagged by the EDR)
    rule.name                          -> ecs_rule
    event.kind                         -> ecs_kind        ('alert' or 'event')
    labels_extra.failed_count_5min     -> failed_count    (EDR's own burst count)
    labels_extra.files_renamed_60s     -> files_renamed

WHY AN EXPLICIT SCHEMA RATHER THAN AUTO-DETECTION
-------------------------------------------------
`union_by_name=true` works but makes DuckDB scan the file to discover columns.
On 15 GB that is an expensive extra pass, and it fails outright if a field's
type changes partway through the file. Declaring the schema costs nothing at
runtime and removes that whole class of failure. Fields absent from a given
record simply arrive as NULL.
"""

# The ECS schema the organisers' generator produces. Declared once, used by the
# parser. Optional blocks (source, destination, winlog, registry, file...)
# appear only on some event types; DuckDB fills the rest with NULL.
ECS_SCHEMA = {
    '"@timestamp"': "VARCHAR",
    "event": ("STRUCT(kind VARCHAR, category VARCHAR[], \"type\" VARCHAR[], "
              "action VARCHAR, severity INTEGER, outcome VARCHAR, "
              "dataset VARCHAR)"),
    "host": "STRUCT(name VARCHAR, ip VARCHAR[])",
    '"user"': "STRUCT(name VARCHAR, domain VARCHAR)",
    "process": ("STRUCT(pid BIGINT, name VARCHAR, executable VARCHAR, "
                "command_line VARCHAR, \"parent\" STRUCT(pid BIGINT, name VARCHAR))"),
    "source": "STRUCT(ip VARCHAR, port INTEGER)",
    "destination": "STRUCT(ip VARCHAR, port INTEGER, domain VARCHAR)",
    "network": "STRUCT(transport VARCHAR, direction VARCHAR, bytes BIGINT)",
    "dns": "STRUCT(question STRUCT(name VARCHAR, \"type\" VARCHAR))",
    "file": "STRUCT(path VARCHAR, extension VARCHAR)",
    "registry": "STRUCT(path VARCHAR)",
    "winlog": "STRUCT(event_id INTEGER)",
    "threat": ("STRUCT(framework VARCHAR, "
               "technique STRUCT(id VARCHAR[], name VARCHAR[]), "
               "tactic STRUCT(name VARCHAR[]))"),
    "rule": "STRUCT(id VARCHAR, name VARCHAR, severity VARCHAR)",
    "labels_extra": "STRUCT(failed_count_5min INTEGER, files_renamed_60s INTEGER)",
}

# The flat columns this adapter produces. parser.py builds its queries against
# these names, so they must match LOG_SCHEMA plus the ECS-only extras.
FLAT_COLUMNS = [
    "timestamp", "host", "user", "event_id", "src_ip", "dest_ip", "status",
    "process", "bytes_out", "message",
    # ECS-only additions, usable by rules in rules_ecs.yaml:
    "ecs_kind", "ecs_technique", "ecs_technique_name", "ecs_tactic",
    "ecs_rule", "ecs_severity", "event_category", "event_action",
    "failed_count", "files_renamed", "dest_domain", "registry_path",
    "file_extension", "process_parent", "command_line",
]


def ecs_schema_sql():
    """Render the ECS schema as a DuckDB `columns={...}` clause."""
    inner = ", ".join(f"{k}: '{v}'" for k, v in ECS_SCHEMA.items())
    return f"columns={{{inner}}}"


def ecs_source_expr(log_path):
    """
    Build the SQL that reads ECS NDJSON and presents it with flat column names.

    Returned as a sub-select, so callers can treat it exactly like a table and
    every existing rule's WHERE clause keeps working untouched.

    COALESCE on src_ip is worth noting: an authentication alert carries the
    attacker's address in `source.ip`, while a process event has no source block
    at all and the relevant address is the host's own. Falling back to the first
    host IP means correlation still has something to join on rather than a NULL.
    """
    if "'" in log_path:
        raise ValueError("Log path may not contain a single quote.")

    return f"""(
        SELECT
            "@timestamp"                        AS timestamp,
            host.name                           AS host,
            "user".name                         AS "user",
            COALESCE(winlog.event_id, 0)        AS event_id,
            COALESCE(source.ip, host.ip[1], '') AS src_ip,
            COALESCE(destination.ip, '')        AS dest_ip,
            COALESCE(event.outcome, '')         AS status,
            COALESCE(process.name, '')          AS process,
            COALESCE(network.bytes, 0)          AS bytes_out,
            -- Keep the command line in `message` for process events. It is the
            -- only place the detections table can carry it, and the correlation
            -- engine needs it to spot `net user <name> /add` -- the event that
            -- links a newly created backdoor account to whoever created it.
            CASE WHEN COALESCE(process.command_line, '') <> ''
                 THEN process.command_line
                 ELSE COALESCE(rule.name, event.action, '') END AS message,
            COALESCE(event.kind, '')            AS ecs_kind,
            COALESCE(threat.technique.id[1], '')    AS ecs_technique,
            COALESCE(threat.technique.name[1], '')  AS ecs_technique_name,
            COALESCE(threat.tactic.name[1], '')     AS ecs_tactic,
            COALESCE(rule.name, '')             AS ecs_rule,
            COALESCE(rule.severity, '')         AS ecs_severity,
            COALESCE(event.category[1], '')     AS event_category,
            COALESCE(event.action, '')          AS event_action,
            COALESCE(labels_extra.failed_count_5min, 0)  AS failed_count,
            COALESCE(labels_extra.files_renamed_60s, 0)  AS files_renamed,
            COALESCE(destination.domain, '')    AS dest_domain,
            COALESCE(registry.path, '')         AS registry_path,
            COALESCE(file.extension, '')        AS file_extension,
            COALESCE(process."parent".name, '') AS process_parent,
            COALESCE(process.command_line, '')  AS command_line
        FROM read_ndjson('{log_path}', {ecs_schema_sql()}, ignore_errors=true)
    )"""


def detect_format(log_path, sample_lines=50):
    """
    Decide whether a file is ECS or our flat format, by looking at it.

    Auto-detection beats a command-line flag here: the judges will point the
    tool at their own file, and a wrong flag produces a confusing empty result
    rather than an obvious error. An ECS record always has a nested "event"
    object and an "@timestamp"; the flat format has neither.

    Reads only the first few lines, so this is cheap even on a 15 GB file.
    """
    import json

    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in range(sample_lines):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if "@timestamp" in rec or isinstance(rec.get("event"), dict):
                    return "ecs"
                if "timestamp" in rec and not isinstance(rec.get("host"), dict):
                    return "flat"
    except OSError:
        pass
    # Default to flat: it is the simpler reader, and a wrong guess shows up
    # immediately as zero detections rather than a crash.
    return "flat"
