"""
inferred_adapter.py -- Read logs whose schema is unknown or scrambled.

WHY THIS FILE EXISTS
--------------------
The other four adapters each recognise one known layout. A file with renamed
keys (`sip` instead of `src_ip`), keys in a different order, no keys at all
(a headerless CSV), or epoch timestamps matched none of them and fell through
to the flat JSON reader -- which found no `timestamp`, `host` or `event_id`
and silently produced zero detections. Zero detections on a real attack, with
no explanation, is the worst result this tool can give.

HOW IT WORKS
------------
1. Read a SAMPLE of the file (the first ~200 non-empty lines) -- never the
   whole file.
2. Work out the container: JSON lines, key=value, CSV/TSV (with or without a
   header), or whitespace-separated tokens.
3. Map columns onto the schema the rules use (LOG_SCHEMA in parser.py):
     * by NAME when there are names: an alias dictionary, then fuzzy matching
       on the normalised name (lowercase, `_-.@ ` removed);
     * by VALUE when there are none, or a name means nothing: each column's
       values are classified (timestamp, IP, integer, status word, process
       name, ...) and the column takes the type most of its values have.
   A name match is accepted only if the values agree with it -- a key called
   `target` is not a destination IP when it holds `audit_policy`.
4. Emit ONE streaming DuckDB expression, exactly like the other adapters, that
   renames the columns and normalises the timestamp into the ISO text the rest
   of the pipeline expects. Unmapped fields are NULL of the right type.

The mapping is scored 0..1 and printed. If no timestamp, or none of
src_ip/host/user, can be found, inference declines (returns None) rather than
guess -- a confident wrong mapping is worse than a clear "unknown format".

APPLICATION-LOG VOCABULARY: a scrambled copy of sample1.log has no Windows
event IDs; its rules (rules_applog.yaml) key on what was done (`action`) and
what changed (`change`). Those two are inferred as well, as `app_action` and
`app_change`, and when an action field is found the application-log rules are
used. These are the only columns emitted beyond LOG_SCHEMA.
"""

import csv
import difflib
import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

SAMPLE_LINES = 200

# Kept in step with parser.LOG_SCHEMA (not imported: parser imports us).
SCHEMA = {
    "timestamp": "VARCHAR", "host": "VARCHAR", "user": "VARCHAR",
    "event_id": "INTEGER", "src_ip": "VARCHAR", "dest_ip": "VARCHAR",
    "status": "VARCHAR", "process": "VARCHAR", "bytes_out": "BIGINT",
    "message": "VARCHAR",
}
APP_FIELDS = {"app_action": "VARCHAR", "app_change": "VARCHAR"}

# Names a field goes by in the wild. Compared after normalising (see _norm).
ALIASES = {
    "timestamp": ["timestamp", "ts", "time", "t", "@t", "@timestamp", "datetime",
                  "date_time", "eventtime", "event_time", "logtime", "log_time",
                  "created", "created_at", "occurred", "occurred_at", "when",
                  "time_generated", "received_at", "event_ts"],
    "host": ["host", "hostname", "host_name", "computer", "computer_name",
             "machine", "device", "devname", "device_name", "node", "server",
             "workstation", "endpoint", "asset", "dvc"],
    "user": ["user", "username", "user_name", "uname", "usr", "account",
             "account_name", "login", "principal", "actor", "subject_user",
             "userid", "user_id", "src_user"],
    "event_id": ["event_id", "eventid", "eid", "evt_id", "evtid", "event_code",
                 "eventcode", "win_event_id", "winlog_event_id", "logid",
                 "log_id", "event_type_id"],
    "src_ip": ["src_ip", "srcip", "sip", "src", "source", "source_ip",
               "sourceip", "source_address", "client", "client_ip", "clientip",
               "remote_ip", "remote_addr", "src_addr", "srcaddr", "from_ip",
               "caller_ip", "origin_ip", "ip"],
    "dest_ip": ["dest_ip", "destip", "dst_ip", "dstip", "dst", "dest",
                "destination", "destination_ip", "destination_address",
                "target_ip", "server_ip", "to_ip", "dst_addr", "dstaddr"],
    "status": ["status", "result", "outcome", "state", "disposition", "res",
               "event_outcome", "auth_result"],
    "process": ["process", "proc", "proc_name", "process_name", "procname",
                "image", "exe", "executable", "binary", "program", "app_name"],
    "bytes_out": ["bytes_out", "bytesout", "bytes", "bytes_sent", "sent_bytes",
                  "sentbytes", "out_bytes", "tx_bytes", "txbytes", "byte_count",
                  "bytecount", "octets_out", "size"],
    "message": ["message", "msg", "description", "desc", "text", "details",
                "detail", "summary", "log_message"],
    "app_action": ["action", "act", "activity", "operation", "op", "verb",
                   "event_action", "evt_action"],
    "app_change": ["change", "changes", "modification", "mod", "delta"],
}

FUZZY_CUTOFF = 0.8


def _norm(name):
    return re.sub(r"[\s_\-.@]", "", str(name).lower())


_ALIAS_INDEX = {}
for _field, _names in ALIASES.items():
    for _n in _names:
        _ALIAS_INDEX.setdefault(_norm(_n), _field)


# ---------------------------------------------------------------------------
# Value classifiers
# ---------------------------------------------------------------------------
_IPV4 = re.compile(r"^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$")
_IPV6 = re.compile(r"^(?=.*:.*:)[0-9A-Fa-f:]{2,39}(?:%\w+)?$")
_INT = re.compile(r"^-?\d+$")
_FLOAT = re.compile(r"^-?\d+\.\d+$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_TIME = re.compile(r"^\d{2}:\d{2}:\d{2}(?:\.\d+)?$")
_TZ_TAIL = re.compile(r"\s*(?:Z|[+-]\d{2}:?\d{2})$")
_STATUS = {"success", "succeeded", "successful", "ok", "failed", "failure",
           "fail", "error", "blocked", "block", "allow", "allowed", "accept",
           "accepted", "deny", "denied", "drop", "dropped", "reset", "pass",
           "passed", "reject", "rejected", "timeout"}
_LEVELS = {"debug", "info", "notice", "warn", "warning", "err", "error", "crit",
           "critical", "alert", "emerg", "fatal", "trace"}
_PROCESS = re.compile(
    r"(?i)(?:\.(?:exe|dll|ps1|bat|cmd|sh|py|bin|com|scr|msi|vbs|jar)$"
    r"|^/(?:usr/)?s?bin/\S+$)")
_ACTION_WORDS = {"login", "logon", "logout", "logoff", "signin", "signout",
                 "create", "created", "delete", "deleted", "modify", "modified",
                 "update", "updated", "request", "dump", "export", "import",
                 "check", "access", "read", "write", "upload", "download",
                 "exec", "execute", "start", "stop", "grant", "revoke", "reset",
                 "change", "changed", "add", "added", "remove", "removed"}
_CHANGE = re.compile(r"(?i)^(?:enable|disable|enabled|disabled|turn_?on|turn_?off"
                     r"|set|unset|add|remove)[_\-:]")
_HOSTNAME = re.compile(
    r"^(?:[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9\-]+|[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+)$")
_TOKEN = re.compile(r"^[^\s/=]+$")
_COMMON_ACCOUNTS = {"admin", "administrator", "root", "system", "guest",
                    "sysadmin", "service", "operator"}

# Text timestamp formats, tried in Python on the sample and handed to DuckDB's
# try_strptime. Both use the same directives for everything listed here.
TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M", "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S", "%d %b %Y %H:%M:%S", "%b %d %Y %H:%M:%S",
    "%b %d %H:%M:%S",
]
# Epoch magnitudes: digits -> (kind, microseconds per unit).
EPOCH_KINDS = {10: ("epoch_s", 1_000_000), 13: ("epoch_ms", 1_000),
               16: ("epoch_us", 1), 19: ("epoch_ns", None)}
_EPOCH_MIN, _EPOCH_MAX = 946684800, 4102444800        # 2000-01-01 .. 2100-01-01

# Leading timestamps in front of key=value pairs (`2026-10-30 08:48:36 INFO
# [auth] user=...`): regex for the SQL, and the formats that parse it.
PREFIX_TS = [
    (r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?", None),
    (r"\d{10}(?:\.\d+)?|\d{13}|\d{16}|\d{19}", "epoch"),
    (r"[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}", None),
    (r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}", None),
]


def _epoch_kind(v):
    if not re.match(r"^\d{10}(?:\.\d+)?$|^\d{13}$|^\d{16}$|^\d{19}$", v):
        return None
    digits = len(v.split(".")[0])
    seconds = float(v) / (10 ** (digits - 10))
    return EPOCH_KINDS[digits][0] if _EPOCH_MIN <= seconds <= _EPOCH_MAX else None


def _text_ts_formats(v):
    v = _TZ_TAIL.sub("", v.strip())
    out = []
    for fmt in TS_FORMATS:
        try:
            datetime.strptime(v, fmt)
            out.append(fmt)
        except ValueError:
            pass
    return out


def classify(v):
    """The type of one value, as a short label. '' for empty."""
    v = str(v).strip()
    if not v or v in ("-", "null", "None"):
        return ""
    if _epoch_kind(v):
        return "epoch"
    if _text_ts_formats(v):
        return "ts"
    if _DATE.match(v):
        return "date"
    if _TIME.match(v):
        return "time"
    if _IPV4.match(v) or (_IPV6.match(v) and not _INT.match(v)):
        return "ip"
    if _INT.match(v):
        return "int"
    if _FLOAT.match(v):
        return "float"
    low = v.lower()
    if low in _STATUS:
        return "status"
    if low in _LEVELS and v.isupper():
        return "level"
    if _PROCESS.search(v):
        return "process"
    if _CHANGE.match(v):
        return "change"
    if "_" in v and _TOKEN.match(v) and any(p in _ACTION_WORDS for p in low.split("_")):
        return "action"
    if " " in v.strip():
        return "text"
    if _HOSTNAME.match(v) and (any(c.isupper() for c in v) or "." in v):
        return "host"
    if _TOKEN.match(v):
        return "word"
    return "other"


def _userish(v):
    low = v.lower()
    return bool(re.search(r"[\d_.@\\]", v)) or low in _COMMON_ACCOUNTS


# ---------------------------------------------------------------------------
# Reading the sample
# ---------------------------------------------------------------------------
def _sample(log_path, n=SAMPLE_LINES):
    lines = []
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\r\n")
            if line.strip():
                lines.append(line)
                if len(lines) >= n:
                    break
    return lines


_KV_PAIR = re.compile(r'(?:^|\s)([A-Za-z_@][\w.@\-]*)=("[^"]*"|\S*)')


def _kv_pairs(line):
    return {k: (v[1:-1] if v.startswith('"') and v.endswith('"') else v)
            for k, v in _KV_PAIR.findall(line)}


def _kv_prefix(line):
    m = _KV_PAIR.search(line)
    return line[:m.start()].strip() if m else line.strip()


def _container(lines):
    """('json'|'kv'|'csv'|'whitespace', detail) for the sample."""
    n = len(lines)
    parsed = []
    for line in lines:
        try:
            rec = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(rec, dict):
            parsed.append(rec)
    if parsed and len(parsed) >= 0.8 * n:
        return "json", parsed

    if sum(1 for line in lines if len(_KV_PAIR.findall(line)) >= 2) >= 0.8 * n:
        return "kv", None

    try:
        dialect = csv.Sniffer().sniff("\n".join(lines[:50]), delimiters=",\t;|")
        rows = list(csv.reader(io.StringIO("\n".join(lines)), delimiter=dialect.delimiter))
        widths = Counter(len(r) for r in rows)
        width, count = widths.most_common(1)[0]
        if width >= 3 and count >= 0.8 * len(rows):
            return "csv", (dialect.delimiter, rows, width)
    except csv.Error:
        pass
    return "whitespace", None


def _looks_like_header(first, rest):
    """A header row: every cell a name, and its types differ from the data."""
    if not all(re.match(r"^[A-Za-z_@#][\w @#.\-]*$", c.strip() or "_") for c in first):
        return False
    for i, cell in enumerate(first):
        types = Counter(classify(r[i]) for r in rest if i < len(r))
        types.pop("", None)
        if types:
            top = types.most_common(1)[0][0]
            if top in ("ts", "epoch", "ip", "int", "float", "date") and classify(cell) != top:
                return True
    return False


# ---------------------------------------------------------------------------
# Mapping
# ---------------------------------------------------------------------------
def _profile(values):
    vals = [str(v).strip() for v in values]
    nonempty = [v for v in vals if v and v not in ("-", "null", "None")]
    types = Counter(classify(v) for v in nonempty)
    return {"fill": len(nonempty) / max(len(vals), 1), "n": len(nonempty),
            "types": types, "values": nonempty}


def _share(p, *kinds):
    return sum(p["types"][k] for k in kinds) / p["n"] if p["n"] else 0.0


def _compatible(field, p):
    """Do a column's values fit the field its name suggests? (0..1)"""
    if not p["n"]:
        return 1.0                      # nothing to contradict the name
    if field == "timestamp":
        return _share(p, "ts", "epoch")
    if field in ("src_ip", "dest_ip"):
        return _share(p, "ip")
    if field in ("event_id", "bytes_out"):
        return _share(p, "int", "float")
    if field == "message":
        return 1.0
    return 1.0 - _share(p, "ip", "ts", "epoch")


def _by_name(columns, profiles):
    """{field: (column, score, how)} from column names."""
    best = {}
    for col in columns:
        key = _norm(col)
        field, how, score = _ALIAS_INDEX.get(key), "alias", 1.0
        if not field:
            close = difflib.get_close_matches(key, _ALIAS_INDEX, n=1, cutoff=FUZZY_CUTOFF)
            if not close:
                continue
            field, how = _ALIAS_INDEX[close[0]], f"fuzzy ({close[0]})"
            score = 0.9 * difflib.SequenceMatcher(None, key, close[0]).ratio()
        fit = _compatible(field, profiles[col])
        if fit < 0.6:
            continue
        score *= fit
        if field not in best or score > best[field][1]:
            best[field] = (col, round(score, 2), how)
    return best


def _by_value(columns, profiles, taken, mapped):
    """Fill unmapped fields from the values of unclaimed columns."""
    out = {}

    def free():
        return [c for c in columns if c not in taken and profiles[c]["n"]]

    def claim(field, col, score, how="values"):
        out[field] = (col, round(score, 2), how)
        taken.add(col)

    def pick(field, kinds, threshold=0.6, prefer=None):
        if field in mapped or field in out:
            return
        cands = [(c, _share(profiles[c], *kinds)) for c in free()]
        cands = [(c, s) for c, s in cands if s >= threshold]
        if not cands:
            return
        key = prefer or (lambda cs: (cs[1] * profiles[cs[0]]["fill"], cs[1]))
        col, s = max(cands, key=key)
        claim(field, col, 0.75 * s)

    pick("timestamp", ("ts", "epoch"))

    # Two IP columns: decide which is the source.
    if "src_ip" not in mapped or "dest_ip" not in mapped:
        ips = [c for c in free() if _share(profiles[c], "ip") >= 0.6]
        if len(ips) >= 2 and "src_ip" not in mapped and "dest_ip" not in mapped:
            src, dst, why = _order_ips(ips[:2], columns, profiles)
            claim("src_ip", src, 0.7, f"values ({why})")
            claim("dest_ip", dst, 0.7, f"values ({why})")
        elif ips:
            claim("dest_ip" if "src_ip" in mapped else "src_ip", ips[0], 0.7)

    # Integers: byte counts are mostly zero or exceed any port/event number;
    # the event ID is then the fullest integer column left.
    ints = [c for c in free() if _share(profiles[c], "int") >= 0.9]
    if "bytes_out" not in mapped:
        def bytes_like(c):
            nums = [int(v) for v in profiles[c]["values"] if _INT.match(v)]
            return nums and (max(nums) > 65535 or sum(n == 0 for n in nums) >= 0.5 * len(nums))
        cands = [c for c in ints if bytes_like(c)]
        if cands:
            col = max(cands, key=lambda c: profiles[c]["fill"])
            claim("bytes_out", col, 0.65)
            ints.remove(col)
    if "event_id" not in mapped and ints:
        col = max(ints, key=lambda c: (profiles[c]["fill"],
                                       -len(set(profiles[c]["values"]))))
        claim("event_id", col, 0.6)

    pick("status", ("status",), 0.5)
    pick("app_action", ("action",), 0.5)
    pick("app_change", ("change",), 0.5)
    pick("process", ("process",), 0.5)
    pick("host", ("host",), 0.6)
    pick("message", ("text",), 0.5)

    if "user" not in mapped:
        best = None
        for c in free():
            p = profiles[c]
            if _share(p, "word", "host") < 0.8:
                continue
            ish = sum(_userish(v) for v in p["values"]) / p["n"]
            score = p["fill"] * (0.5 + 0.5 * ish)
            if best is None or score > best[1]:
                best = (c, score)
        if best and best[1] >= 0.4:
            claim("user", best[0], 0.6 * best[1])
    return out


def _order_ips(ips, columns, profiles):
    """(src, dest, reason) for two IP columns."""
    a, b = ips
    ia, ib = columns.index(a), columns.index(b)

    def port_after(i):
        if i + 1 < len(columns):
            p = profiles[columns[i + 1]]
            nums = [int(v) for v in p["values"] if _INT.match(v)]
            if nums and _share(p, "int") >= 0.9 and max(nums) <= 65535:
                return sum(n >= 32768 for n in nums) / len(nums)
        return None

    pa, pb = port_after(ia), port_after(ib)
    if pa is not None and pb is not None and abs(pa - pb) >= 0.5:
        return (a, b, "ephemeral port") if pa > pb else (b, a, "ephemeral port")
    fa, fb = profiles[a]["fill"], profiles[b]["fill"]
    if abs(fa - fb) >= 0.2:
        # A source address is on nearly every record; a destination only on
        # those that reach somewhere (the flat sample: 100% vs ~10%).
        return (a, b, "fill rate") if fa > fb else (b, a, "fill rate")

    def private(c):
        vals = profiles[c]["values"]
        return sum(bool(re.match(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)", v))
                   for v in vals) / max(len(vals), 1)
    if abs(private(a) - private(b)) >= 0.3:
        return (a, b, "private range") if private(a) > private(b) else (b, a, "private range")
    return (a, b, "column order") if ia < ib else (b, a, "column order")


def _ts_spec(values):
    """How to parse a timestamp column: ('epoch_ms', None) or ('text', [fmts])."""
    vals = [str(v).strip() for v in values if str(v).strip()]
    kinds = Counter(_epoch_kind(v) for v in vals)
    kinds.pop(None, None)
    if kinds and sum(kinds.values()) >= 0.6 * len(vals):
        return kinds.most_common(1)[0][0], None
    hits = Counter(f for v in vals for f in _text_ts_formats(v))
    if not hits:
        return None, None
    # Day-first and month-first both parse 01/02; keep only the one that
    # parses more of the sample, so the order is decided by the data.
    if "%d/%m/%Y %H:%M:%S" in hits and "%m/%d/%Y %H:%M:%S" in hits:
        hits.pop("%m/%d/%Y %H:%M:%S" if hits["%d/%m/%Y %H:%M:%S"] >=
                 hits["%m/%d/%Y %H:%M:%S"] else "%d/%m/%Y %H:%M:%S")
    # A whole second is often written without its fraction (Python's
    # isoformat does this), so each format brings its twin: a row the sample
    # never showed must not be dropped for lacking ".000".
    fmts = []
    for f, _ in hits.most_common():
        for g in (f, f.replace(".%f", "") if ".%f" in f else
                  (f + ".%f" if f.endswith("%S") else None)):
            if g and g not in fmts:
                fmts.append(g)
    return "text", fmts


def _merge_date_time(columns, profiles):
    """Separate date and time columns become one timestamp source."""
    for i, c in enumerate(columns[:-1]):
        d = columns[i + 1]
        if _share(profiles[c], "date") >= 0.9 and _share(profiles[d], "time") >= 0.9:
            return (c, d)
    return None


def infer(log_path):
    """The full inference: mapping dict, or None with the reason why."""
    lines = _sample(log_path)
    if not lines:
        return None, "the file is empty"
    container, detail = _container(lines)
    mapping = {"container": container, "sample_lines": len(lines), "notes": []}

    if container == "json":
        keys = list(dict.fromkeys(k for rec in detail for k in rec))
        columns, keyed = keys, True
        values = {k: ["" if rec.get(k) is None else
                      (json.dumps(rec[k]) if isinstance(rec.get(k), (dict, list))
                       else str(rec.get(k))) for rec in detail] for k in keys}
    elif container == "kv":
        recs = [_kv_pairs(line) for line in lines]
        keys = list(dict.fromkeys(k for r in recs for k in r))
        columns, keyed = keys, True
        values = {k: [r.get(k, "") for r in recs] for k in keys}
        # A timestamp written in front of the pairs, as in sample1.log.
        prefixes = [_kv_prefix(line) for line in lines]
        for regex, kind in PREFIX_TS:
            got = [m.group(0) for p in prefixes for m in [re.match(regex, p)] if m]
            if len(got) >= 0.8 * len(lines):
                mapping["prefix_ts"] = regex
                values["(leading timestamp)"] = got
                columns = ["(leading timestamp)"] + columns
                break
    elif container == "csv":
        delim, rows, width = detail
        mapping.update(delimiter=delim, width=width)
        header = _looks_like_header(rows[0], rows[1:])
        mapping["header"] = header
        data = rows[1:] if header else rows
        names = ([c.strip() for c in rows[0]] if header else
                 [f"column {i + 1}" for i in range(width)])
        columns, keyed = names, header
        values = {names[i]: [r[i] if i < len(r) else "" for r in data]
                  for i in range(width)}
    else:
        toks = [line.split() for line in lines]
        width = Counter(len(t) for t in toks).most_common(1)[0][0]
        mapping["width"] = width
        names = [f"token {i + 1}" for i in range(width)]
        columns, keyed = names, False
        values = {names[i]: [t[i] if i < len(t) else "" for t in toks]
                  for i in range(width)}
        mapping["notes"].append("whitespace tokens: a free-text message "
                                "cannot be recovered from split words")

    mapping["columns"] = columns
    profiles = {c: _profile(values[c]) for c in columns}
    fields = _by_name(columns, profiles) if keyed else {}
    if container == "kv" and "prefix_ts" in mapping and "timestamp" not in fields:
        fields["timestamp"] = ("(leading timestamp)", 0.9, "leading text")
    taken = {c for c, _, _ in fields.values()}

    merged = None
    if "timestamp" not in fields and container in ("csv", "whitespace"):
        merged = _merge_date_time(columns, profiles)
        if merged:
            fields["timestamp"] = (merged, 0.75, "values (date + time columns)")
            taken |= set(merged)
    fields.update(_by_value(columns, profiles, taken, set(fields)))

    if "timestamp" not in fields:
        return None, "no column holds timestamps"
    if not any(f in fields for f in ("src_ip", "host", "user")):
        return None, "no source address, host or account column was found"

    ts_col = fields["timestamp"][0]
    ts_values = ([f"{a} {b}" for a, b in zip(values[merged[0]], values[merged[1]])]
                 if merged else values[ts_col])
    kind, fmts = _ts_spec(ts_values)
    if not kind:
        return None, f"timestamp column {ts_col!r} could not be parsed"
    mapping["ts_kind"], mapping["ts_formats"] = kind, fmts

    mapping["fields"] = {f: {"source": c, "score": s, "how": h}
                         for f, (c, s, h) in fields.items()}
    mapping["confidence"] = round(
        sum(fields[f][1] for f in SCHEMA if f in fields) / len(SCHEMA), 2)
    mapping["rules"] = "rules_applog.yaml" if "app_action" in fields else "rules.yaml"
    if kind == "text" and fmts and fmts[0] == "%b %d %H:%M:%S":
        mapping["notes"].append("timestamps carry no year; the year reads as 1900")
    return mapping, None


_CACHE = {}


def detect_inferred(log_path):
    """The inferred mapping for a file, or None if it cannot be inferred."""
    try:
        st = os.stat(log_path)
    except OSError:
        return None
    key = (os.path.abspath(log_path), st.st_mtime_ns, st.st_size)
    if key not in _CACHE:
        try:
            _CACHE[key] = infer(log_path)
        except (OSError, UnicodeError) as exc:
            _CACHE[key] = (None, str(exc))
    return _CACHE[key][0]


def why_not(log_path):
    """Why inference declined, for the error message."""
    detect_inferred(log_path)
    st = os.stat(log_path)
    return _CACHE.get((os.path.abspath(log_path), st.st_mtime_ns, st.st_size),
                      (None, "unknown"))[1]


# ---------------------------------------------------------------------------
# SQL
# ---------------------------------------------------------------------------
def _esc(text):
    """Escape for a single-quoted SQL string literal."""
    return str(text).replace("'", "''")


def _ident(name):
    """Escape for a double-quoted SQL identifier."""
    return '"' + str(name).replace('"', '""') + '"'


def _lines_reader(log_path):
    # Same reader settings as fortigate_adapter.py / applog_adapter.py: one
    # whole line per row, no CSV quote handling, tolerate malformed lines.
    return (f"read_csv('{_esc(log_path)}', delim='\\x07', header=false, "
            f"columns={{'line': 'VARCHAR'}}, ignore_errors=true, "
            f"quote='', escape='', strict_mode=false)")


def inferred_source_expr(log_path, mapping):
    """
    One streaming DuckDB sub-select presenting the file with the flat schema.

    Only mapped columns are extracted, so a key=value file runs one regex per
    mapped field, not one per key seen.
    """
    if "'" in log_path:
        raise ValueError("Log path may not contain a single quote.")
    fields = mapping["fields"]
    container = mapping["container"]
    sources = {}
    for f in fields.values():
        src = f["source"]
        for s in (src if isinstance(src, (list, tuple)) else [src]):
            sources.setdefault(s, f"_s{len(sources)}")

    if container == "json":
        cols = ", ".join(f"'{_esc(s)}': 'VARCHAR'" for s in sources)
        raw = (f"(SELECT {', '.join(f'{_ident(s)} AS {a}' for s, a in sources.items())} "
               f"FROM read_ndjson('{_esc(log_path)}', columns={{{cols}}}, "
               f"ignore_errors=true))")
    elif container == "kv":
        exprs = []
        for s, a in sources.items():
            if s == "(leading timestamp)":
                pat = rf"^\s*({mapping['prefix_ts']})"
                exprs.append(f"regexp_extract(line, '{_esc(pat)}', 1) AS {a}")
            else:
                pat = rf'(?:^|\s){re.escape(s)}=(?:"([^"]*)"|(\S*))'
                exprs.append(f"COALESCE(NULLIF(regexp_extract(line, '{_esc(pat)}', 1), ''), "
                             f"regexp_extract(line, '{_esc(pat)}', 2)) AS {a}")
        raw = f"(SELECT {', '.join(exprs)} FROM {_lines_reader(log_path)})"
    elif container == "csv":
        names = mapping["columns"]
        width = mapping["width"]
        cols = ", ".join(f"'c{i}': 'VARCHAR'" for i in range(width))
        delim = _esc(mapping["delimiter"])
        raw = (f"(SELECT {', '.join(f'c{names.index(s)} AS {a}' for s, a in sources.items())} "
               f"FROM read_csv('{_esc(log_path)}', delim='{delim}', "
               f"header={'true' if mapping['header'] else 'false'}, "
               f"columns={{{cols}}}, quote='\"', escape='\"', ignore_errors=true, "
               f"null_padding=true, strict_mode=false))")
    else:
        names = mapping["columns"]
        raw = (f"(SELECT {', '.join(f'_tok[{names.index(s) + 1}] AS {a}' for s, a in sources.items())} "
               f"FROM (SELECT string_split(regexp_replace(trim(line), '\\s+', ' ', 'g'), ' ') "
               f"AS _tok FROM {_lines_reader(log_path)}))")

    def ref(field):
        src = fields[field]["source"]
        if isinstance(src, (list, tuple)):
            return " || ' ' || ".join(sources[s] for s in src)
        return sources[src]

    # Timestamp, normalised to the ISO text every other adapter produces:
    # seconds precision, plus microseconds only when there are any.
    v = ref("timestamp")
    kind = mapping["ts_kind"]
    if kind == "text":
        fmts = ", ".join(f"'{_esc(f)}'" for f in mapping["ts_formats"])
        ts = (f"try_strptime(regexp_replace(trim({v}), '\\s*(Z|[+-]\\d{{2}}:?\\d{{2}})$', ''), "
              f"[{fmts}])")
    elif kind == "epoch_ns":
        ts = f"make_timestamp(TRY_CAST({v} AS BIGINT) // 1000)"
    else:
        per = {"epoch_s": 1_000_000, "epoch_ms": 1_000, "epoch_us": 1}[kind]
        ts = f"make_timestamp(CAST(TRY_CAST({v} AS DOUBLE) * {per} AS BIGINT))"

    select = []
    for field, typ in {**SCHEMA, **(APP_FIELDS if "app_action" in fields else {})}.items():
        if field == "timestamp":
            continue
        if field not in fields:
            select.append(f"CAST(NULL AS {typ}) AS {_ident(field)}")
        elif typ == "INTEGER":
            select.append(f"TRY_CAST(TRY_CAST({ref(field)} AS DOUBLE) AS INTEGER) AS {_ident(field)}")
        elif typ == "BIGINT":
            select.append(f"TRY_CAST(TRY_CAST({ref(field)} AS DOUBLE) AS BIGINT) AS {_ident(field)}")
        else:
            select.append(f"COALESCE(CAST({ref(field)} AS VARCHAR), '') AS {_ident(field)}")

    return f"""(
        SELECT
            CASE WHEN epoch_us(_ts) % 1000000 = 0
                 THEN strftime(_ts, '%Y-%m-%dT%H:%M:%S')
                 ELSE strftime(_ts, '%Y-%m-%dT%H:%M:%S.%f') END AS timestamp,
            {', '.join(select)}
        FROM (SELECT {ts} AS _ts, * FROM {raw})
        WHERE _ts IS NOT NULL
    )"""


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def critical_fields(rules):
    """Fields each rule's condition or grouping reads: {field: [rule names]}."""
    known = set(SCHEMA) | set(APP_FIELDS)
    out = {}
    for r in rules:
        words = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", r.get("sql_condition", "")))
        words |= set(r.get("group_by") or [])
        for w in words & known:
            out.setdefault(w, []).append(r["name"])
    return out


def report(mapping, rules, stream=None):
    """Print the mapping, its confidence, and any rule left blind, to stderr."""
    stream = stream or sys.stderr
    p = lambda s="": print(s, file=stream)  # noqa: E731
    extra = (f", delimiter {mapping['delimiter']!r}, header "
             f"{'yes' if mapping['header'] else 'no'}" if mapping["container"] == "csv" else "")
    p(f"  INFERRED SCHEMA  container {mapping['container']}{extra}, "
      f"from {mapping['sample_lines']} sample lines")
    ts = mapping["ts_kind"] if mapping["ts_kind"] != "text" else mapping["ts_formats"][0]
    for field in list(SCHEMA) + [f for f in APP_FIELDS if f in mapping["fields"]]:
        f = mapping["fields"].get(field)
        if f:
            src = f["source"]
            src = " + ".join(src) if isinstance(src, (list, tuple)) else src
            note = f"  [{ts}]" if field == "timestamp" else ""
            p(f"    {field:<10} <- {src!s:<24} {f['how']:<28} {f['score']:.2f}{note}")
        else:
            p(f"    {field:<10} <- (not found)            NULL")
    p(f"  confidence {mapping['confidence']:.2f}   rules {mapping['rules']}")
    for note in mapping["notes"]:
        p(f"  note: {note}")
    blind = {f: names for f, names in critical_fields(rules).items()
             if f not in mapping["fields"]}
    if blind:
        p("  " + "!" * 70)
        p("  WARNING: fields these rules need were not found in the log:")
        for f, names in sorted(blind.items()):
            p(f"    {f:<10} needed by: {', '.join(names)}")
        p("  Those rules cannot fire. Fewer or zero detections is a mapping gap,")
        p("  not proof the log is clean. Rename the column or pass --format.")
        p("  " + "!" * 70)
    return blind
