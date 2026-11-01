"""
app.py -- The analyst's dashboard: timeline, attack graph, and AI narrative.

WHY THIS FILE EXISTS
--------------------
The PRD's "Explain" goal is that an analyst should understand the attack "in a
minute". Everything upstream produced correct data; this file makes it legible.

Three views, because each answers a different question:
    TIMELINE  -> what happened, in what order?   (FR-5)
    GRAPH     -> how are the pieces connected?   (FR-5)
    LOOK-AHEAD-> where could they go next?       (FR-6)
Plus a plain-English summary written by an LLM (bonus B-2).

WHY STREAMLIT: the PRD explicitly says a polished UI is not required, so the
right move is the least UI work that still communicates. Streamlit gives a
browser dashboard with no HTML, no JavaScript and no build step.

A NOTE ON THE LLM: the language model writes the *narration* only. Detection,
correlation, pathfinding and look-ahead are all deterministic and run offline.
If Groq is unreachable the tool still works and still shows the attack -- it
just loses the prose paragraph. That separation is deliberate and worth stating
to judges: the AI is a presentation layer, not a load-bearing component.

SATISFIES
  FR-5  timeline and graph of hosts and users
  FR-6  what the attacker could reach next
  FR-7  simple page, documented in the README
  B-1   incidents ranked by risk score
  B-2   auto-written incident report in plain English
  B-3   raw alerts merged shown per incident
"""

import html
import os
import subprocess
import sys

import duckdb
import streamlit as st

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import graph_engine  # noqa: E402
from elliot import ui as elliot_ui  # noqa: E402

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# WHICH DATABASE THE DASHBOARD OPENS
#
# Each input gets its own database -- chronopath.db for the flat sample,
# firex.db for the organisers' 6.54 GB FortiGate file, edr.db for the ECS
# export. Hardcoding one of them meant the dashboard silently showed the
# sample while the real findings sat in firex.db, which is a confusing way to
# lose a demo.
#
# So: honour CHRONOPATH_DB if the analyst set it, otherwise pick the most
# recently written database that actually holds detections. "Most recent" is
# the right default because it is the one the analyst just produced.
DB_ENV_VAR = "CHRONOPATH_DB"


def _available_databases():
    """
    Every ChronoPath database in the project folder.

    Discovered rather than listed: a fixed list of four names meant a database
    built for any other log (sample1.db, firex30.db) could only be opened via
    the environment variable, and the sidebar's Run detection wrote somewhere
    the page was not looking.
    """
    found = []
    for name in sorted(os.listdir(PROJECT_ROOT)):
        if name.endswith(".db"):
            found.append(os.path.join(PROJECT_ROOT, name))
    return found


def _pick_database():
    # 1. A choice made in the sidebar, or the database Run detection just built.
    chosen = st.session_state.get("db_path")
    if chosen and os.path.exists(chosen):
        return chosen
    # 2. An explicit CHRONOPATH_DB.
    override = os.environ.get(DB_ENV_VAR)
    if override:
        path = override if os.path.isabs(override) else \
            os.path.join(PROJECT_ROOT, override)
        if os.path.exists(path):
            return path
    # 3. The most recently written database.
    existing = _available_databases()
    if not existing:
        return os.path.join(PROJECT_ROOT, "chronopath.db")
    return max(existing, key=os.path.getmtime)


DB_PATH = _pick_database()

# The 2.0 evidence layer. Imported defensively: the dashboard must still open
# on a 1.x database that has never seen chronopath2, showing the four new tabs
# as empty rather than failing to start.
try:
    from chronopath2 import gaps as cp2_gaps
    from chronopath2 import link_evidence as cp2_links
    from chronopath2 import respond as cp2_respond
    from chronopath2 import streams as cp2_streams
    CP2_AVAILABLE = True
except Exception:  # noqa: BLE001
    CP2_AVAILABLE = False


def load_env_file():
    """
    Read GROQ_API_KEY from a local .env file if it is not already set.

    WHY: an environment variable only lives as long as the terminal window that
    set it. During a hackathon you will open new terminals constantly, and
    re-exporting the key every time is an easy thing to forget right before a
    demo. Dropping the key in a .env file once makes it persistent.

    Environment variables still win over the file, so an explicitly exported key
    is never silently overridden.

    SECURITY: .env is listed in .gitignore. A key committed to git is a leaked
    key -- treat it as burned and regenerate it.
    """
    if os.environ.get("GROQ_API_KEY"):
        return
    env_path = os.path.join(PROJECT_ROOT, ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                # Tolerate quotes around the value; people copy keys with them.
                os.environ.setdefault(key.strip(), value.strip().strip('"\''))
    except OSError:
        pass  # A missing or unreadable .env is not an error; we fall back.


load_env_file()

# Colour scheme. Kept as constants so the graph and the legend can never drift
# apart -- a legend that lies is worse than no legend.
COLOR_COMPROMISED = "#e03131"   # red:    confirmed in the attack
COLOR_AT_RISK = "#f59f00"       # amber:  reachable next
COLOR_EXTERNAL = "#862e9c"      # purple: outside the company
COLOR_CLEAN = "#adb5bd"         # grey:   untouched

st.set_page_config(page_title="ChronoPath", page_icon="🕸️", layout="wide")

# Page styling: the look of a plain academic website rather than an app. Serif
# text (STIX Two, the typeface of many maths journals), a centred reading
# column, thin rules instead of boxes, small-caps labels, and none of
# Streamlit's own chrome. Colours come from .streamlit/config.toml. Only looks
# change here -- if the font cannot load, the browser's serif is used.
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=STIX+Two+Text:ital,wght@0,400;0,600;1,400&family=Source+Code+Pro:wght@400;500&display=swap');

html, body, [class*="st-"], .stMarkdown, .stText, button, input, select, textarea {
    font-family: 'STIX Two Text', 'Latin Modern Roman', 'Times New Roman', serif;
}
/* Icons are drawn from a font of their own; the serif rule above must not
   replace it, or the icon's name prints as text ("_arrow_right"). */
[data-testid="stIconMaterial"], .material-symbols-rounded, .material-icons {
    font-family: 'Material Symbols Rounded', 'Material Icons' !important;
}
code, pre, .stCode, [data-testid="stCode"] * {
    font-family: 'Source Code Pro', ui-monospace, monospace !important;
    font-size: 0.86em;
}

/* Streamlit chrome off: no coloured top strip, toolbar or footer. */
header[data-testid="stHeader"] { background: transparent; }
/* The toolbar stays: in Streamlit 1.66 the "open sidebar" arrow sits inside
   it, so hiding the toolbar left no way back once the sidebar was closed.
   Only its other buttons (deploy, menu, status) are hidden. */
[data-testid="stToolbarActions"], [data-testid="stMainMenu"],
[data-testid="stAppDeployButton"], [data-testid="stStatusWidget"] { display: none; }
[data-testid="stExpandSidebarButton"] { display: inline-flex !important; }
[data-testid="stDecoration"], footer { display: none; }

/* A centred reading column, like a page of text. */
[data-testid="stMainBlockContainer"], .block-container {
    max-width: 1080px; padding-top: 1.2rem; padding-bottom: 3rem;
}

/* Masthead and footer. */
.cp-masthead {
    display: flex; justify-content: space-between; align-items: baseline;
    flex-wrap: wrap; gap: .3rem 1.5rem;
    border-bottom: 1px solid #1a1a1a; padding-bottom: .45rem; margin-bottom: .2rem;
}
.cp-masthead .cp-name { font-size: 1.9rem; font-weight: 600; letter-spacing: .01em; }
.cp-masthead .cp-tag  { font-style: italic; color: #555; }
.cp-subline {
    font-size: .85rem; color: #666; font-variant: small-caps; letter-spacing: .05em;
    border-bottom: 1px solid #ddd; padding-bottom: .4rem; margin-bottom: 1.4rem;
}
.cp-footer {
    margin-top: 3rem; padding-top: .6rem; border-top: 1px solid #ccc;
    font-size: .85rem; color: #777; text-align: center;
}

/* Headings: plain serif with a hairline under section titles. */
h1, h2, h3, h4 { font-family: 'STIX Two Text', serif !important; font-weight: 600 !important; }
h2, h3 { border-bottom: 1px solid #e3e3e3; padding-bottom: .25rem; }

/* Metrics read as a row of figures, not cards. */
[data-testid="stMetric"] { border-left: 2px solid #1f4e8c; padding: .1rem 0 .1rem .8rem; }
[data-testid="stMetricLabel"] p {
    font-variant: small-caps; letter-spacing: .05em; color: #555; font-size: .9rem;
}
[data-testid="stMetricValue"] { font-weight: 400; }

/* Tabs as a text navigation bar with an underline on the current page. */
.stTabs [data-baseweb="tab-list"] { gap: 1.4rem; border-bottom: 1px solid #ccc; }
.stTabs button[data-baseweb="tab"] { padding: .35rem 0; background: transparent; }
.stTabs button[data-baseweb="tab"] p { font-size: 1rem; }
.stTabs [data-baseweb="tab-highlight"] { background-color: #1a1a1a; height: 2px; }

/* Boxes become ruled sections. */
[data-testid="stExpander"] details { border: none; border-top: 1px solid #ddd; border-radius: 0; }
[data-testid="stAlert"] { border-radius: 0; }
.stButton button { border-radius: 2px; }

/* Plain tables, the way a paper sets them: rules above and below only. */
[data-testid="stTable"] table { border-collapse: collapse; border-top: 1.5px solid #1a1a1a;
    border-bottom: 1.5px solid #1a1a1a; }
[data-testid="stTable"] th { border-bottom: 1px solid #1a1a1a !important; font-weight: 600; }
[data-testid="stTable"] td, [data-testid="stTable"] th { border-left: none !important;
    border-right: none !important; }

/* The sidebar as a quiet margin column. */
section[data-testid="stSidebar"] { border-right: 1px solid #e3e3e3; }
section[data-testid="stSidebar"] h2 { border-bottom: none; font-size: 1.15rem; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def load_incidents(db_mtime):
    """
    Load and correlate incidents.

    The cache key is the database's modification time, not the path. That means
    the expensive correlation runs once and is reused on every UI interaction,
    but automatically recomputes the moment the parser writes a new database.
    This is what keeps "open an incident" under the PRD's 500 ms target -- the
    work is already done before the analyst clicks.
    """
    return graph_engine.analyse(DB_PATH)


def db_signature():
    # Path as well as mtime: two databases written in the same second must not
    # share cached results when the analyst switches between them.
    return (DB_PATH, os.path.getmtime(DB_PATH) if os.path.exists(DB_PATH) else 0)


def source_log_for_db(sig):
    """The log file this database was built from, if the coverage pass ran."""
    rows = cp2_read(sig, "SELECT path FROM cp2_source_fingerprint "
                         "ORDER BY recorded_at DESC LIMIT 1")
    return rows[0]["path"] if rows else None


# ---------------------------------------------------------------------------
# ChronoPath 2.0 -- the evidence and gap layer
#
# Read-only, and cached on the database's modification time exactly as the
# incident list is, so switching tabs never re-queries. Every reader returns
# an empty list when its table is absent, which is what lets the dashboard
# open on a 1.x database and show these tabs as empty rather than crashing.
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def cp2_read(db_mtime, sql, params=None):
    """Run one read-only query against the 2.0 tables."""
    if not os.path.exists(DB_PATH):
        return []
    try:
        con = duckdb.connect(DB_PATH, read_only=True)
    except Exception:  # noqa: BLE001
        return []
    try:
        rows = con.execute(sql, params or []).fetchall()
        cols = [d[0] for d in con.description]
        return [dict(zip(cols, r)) for r in rows]
    except Exception:  # noqa: BLE001
        # The table does not exist yet -- the 2.0 layer has not been run.
        return []
    finally:
        con.close()


def cp2_has_data(db_mtime):
    """Whether this database carries a 2.0 layer at all."""
    return bool(cp2_read(db_mtime, "SELECT 1 FROM cp2_links LIMIT 1")
                or cp2_read(db_mtime, "SELECT 1 FROM cp2_gaps LIMIT 1"))


def guess_source_log():
    """
    The log this database was built from: the coverage record if there is one,
    otherwise a log file with the same name as the database (sample1.db ->
    sample1.log), which is how Run detection names databases.
    """
    recorded = source_log_for_db(db_signature())
    if recorded and os.path.exists(recorded):
        return recorded
    stem = os.path.splitext(os.path.basename(DB_PATH))[0]
    for folder in (PROJECT_ROOT, os.path.join(PROJECT_ROOT, "data")):
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            base, ext = os.path.splitext(name)
            if base == stem and ext.lower() not in (".db", ".wal"):
                return os.path.join(folder, name)
    return None


def build_cp2_now(key):
    """
    One-click repair for a database without the 2.0 layer -- for example one
    the parser rebuilt on its own, which deletes the file and the layer with it.
    """
    source = guess_source_log()
    if not source:
        return
    rel = os.path.relpath(source, PROJECT_ROOT)
    if st.button(f"Build it now from {rel}", key=key, type="primary"):
        with st.spinner("Building the evidence, gap and coverage layer..."):
            result = subprocess.run(
                [sys.executable,
                 os.path.join(PROJECT_ROOT, "scripts", "run_cp2.py"),
                 "--db", DB_PATH, "--input", source],
                capture_output=True, text=True, cwd=PROJECT_ROOT,
                encoding="utf-8", errors="replace",
                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        if result.returncode == 0:
            st.cache_data.clear()
            st.rerun()
        st.error("Building the 2.0 layer failed")
        st.code((result.stdout + result.stderr)[-1500:], language="text")


def cp2_missing_notice(key="cp2_build"):
    """One consistent message wherever the 2.0 layer has not been built."""
    st.info(
        "The ChronoPath 2.0 evidence layer has not been built for this "
        "database yet. Run:\n\n"
        f"```\npython scripts/run_cp2.py --db {os.path.basename(DB_PATH)} "
        "--input <your log file>\n```")
    build_cp2_now(key)


# ---------------------------------------------------------------------------
# LLM narrative (bonus B-2)
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def generate_report(summary_text, incident_id):
    """
    Ask Groq to turn the structured attack path into a readable paragraph.

    Wrapped in try/except on purpose. A live demo depends on conference wifi and
    a free-tier API; both can fail. If either does we return a clear message
    rather than a stack trace, and the rest of the dashboard carries on. Judges
    notice graceful degradation.

    MODEL CHOICE -- corrected after testing against a real API key, and worth
    recording because the documentation was misleading.

    Groq's public model page lists llama-3.3-70b-versatile as a current
    production model. Calling it with an actual free-tier key returns
    HTTP 404 "model does not exist or you do not have access to it". Querying
    models.list() with that key shows NO Llama chat models at all -- the
    available chat models are openai/gpt-oss-120b, openai/gpt-oss-20b,
    qwen/qwen3.8-27b and allam-2-7b.

    So we use gpt-oss-120b, verified working with this key. The lesson: the
    only trustworthy model list is the one the key itself returns.

    MAX_TOKENS -- also learned the hard way. gpt-oss models emit a hidden
    `reasoning` field before their visible answer, and BOTH draw on the same
    token budget. At max_tokens=700 the budget was consumed by reasoning and
    `content` came back as an empty string with finish_reason='length' -- a
    silent blank report rather than an error. 1500 leaves ample room for both.
    """
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None, "no_key"

    # Tried in order; the first that responds wins. All three were confirmed
    # present on the test key, so this survives one being retired.
    models = ["openai/gpt-oss-120b", "openai/gpt-oss-20b", "qwen/qwen3.8-27b"]

    last_error = "no model responded"
    try:
        from groq import Groq
        client = Groq(api_key=api_key)
    except Exception as exc:
        return str(exc), "error"

    for model in models:
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system",
                     "content": "You are a senior SOC analyst writing an "
                                "incident report for a non-technical "
                                "executive. Be concise, factual, and never "
                                "invent details beyond the data given."},
                    {"role": "user",
                     "content": (
                         "Write a short plain-English incident report from "
                         "this MITRE-tagged attack path. Cover: where the "
                         "attack started, what the attacker did step by step, "
                         "and what they could reach next. Four short "
                         "paragraphs maximum.\n\n" + summary_text)},
                ],
                temperature=0.2,  # low: faithful reporting, not creativity
                max_tokens=1500,
            )
            text = (response.choices[0].message.content or "").strip()
            if text:
                return text, "ok"
            # Empty content is a real outcome, not an exception -- treat it as
            # a failure of this model and try the next rather than showing the
            # analyst a blank panel.
            last_error = f"{model} returned no content"
        except Exception as exc:
            last_error = f"{model}: {exc}"

    return last_error, "error"


def fallback_report(incident):
    """
    A deterministic summary used when the LLM is unavailable.

    This is the demo safety net. It is assembled from the same structured data,
    so it is always accurate -- just less fluent than the model's prose.
    """
    path = graph_engine.get_attack_path(incident)
    ahead = graph_engine.look_ahead(incident)
    if not path:
        return "No events in this incident."

    first, last = path[0], path[-1]
    lines = [
        f"**Summary.** Incident {incident['id']} scores "
        f"{incident['risk_score']}/100. {incident['raw_alert_count']} raw log "
        f"alerts were merged into {incident['detection_count']} distinct "
        f"detections spanning {len(incident['stages'])} kill chain stages.",
        "",
        f"**Entry point.** The first observed step was *{first['rule']}* "
        f"({first['technique']}) on host **{first['host']}** involving account "
        f"**{first['user']}** at {first['timestamp'][:19]}.",
        "",
        f"**Progression.** The attack advanced to *{last['stage']}*, ending with "
        f"*{last['rule']}* ({last['technique']}) on **{last['host']}**. "
        f"Hosts involved: {', '.join(incident['hosts'])}. "
        f"Accounts involved: {', '.join(incident['users'])}.",
    ]
    if ahead:
        targets = ", ".join(a["target"] for a in ahead[:5])
        lines += ["", f"**Exposure.** {len(ahead)} further systems are reachable, "
                      f"including {targets}."]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Graph rendering
# ---------------------------------------------------------------------------
# At most this many nodes per column; the rest fold into one "+N more" node.
GRAPH_COLUMN_CAP = 6


def _step_ranges(steps):
    """[1,2,3,7] -> '1-3, 7'; long lists collapse to a count."""
    steps = sorted(set(steps))
    out, start = [], steps[0]
    for prev, cur in zip(steps, steps[1:] + [None]):
        if cur is None or cur != prev + 1:
            out.append(str(start) if start == prev else f"{start}-{prev}")
            start = cur
    return ", ".join(out) if len(out) <= 3 else f"{len(steps)} steps"


def _dot(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"')


def build_attack_dot(incident, show_context=False):
    """
    The attack graph as Graphviz DOT, laid out left to right as four columns:

        External IPs -> Accounts -> Compromised machines -> Reachable next

    Clutter control, each a deliberate choice:
      * Fixed layered layout, not a physics simulation that moves on every load.
      * One arrow per pair of entities, labelled with the step numbers from
        the Timeline tab, instead of one labelled arrow per alert.
      * Alerts linked only because they hit the same machine at the same time
        (different account) are hidden unless asked for.
      * Each column is capped; the overflow folds into a "+N more" node.
      * Inbound sources sit on the far left and outbound destinations on the
        right, so no arrow runs backwards across the picture. An IP that is
        both appears once on each side.
    """
    path = graph_engine.get_attack_path(incident)
    steps = [(s, e) for s, e in zip(path, incident["events"])
             if show_context or e.get("context") != "host"]

    edges = {}          # (left, right) -> [step numbers]
    severity = {}
    touched = {}        # node id -> set of step numbers
    kind, display = {}, {}

    def link(a, ka, b, kb, n, sev):
        for node, k in ((a, ka), (b, kb)):
            kind.setdefault(node, k)
            display.setdefault(node, node.split(":", 1)[1] if k in ("inbound", "outbound") else node)
            touched.setdefault(node, set()).add(n)
        edges.setdefault((a, b), []).append(n)
        severity[(a, b)] = max(severity.get((a, b), 0), sev)

    for s, e in steps:
        user = None if graph_engine._is_anonymous(e) else e["user"]
        host, src, dst = e.get("host"), e.get("src_ip"), e.get("dest_ip")
        n, sev = s["step"], s["severity"] or 0
        if user and host:
            link(user, "account", host, "host", n, sev)
        if src and host and not graph_engine._is_internal(src) and src != host:
            link(f"in:{src}", "inbound", user or host,
                 "account" if user else "host", n, sev)
        if dst and host and not graph_engine._is_internal(dst) and dst != host:
            link(host, "host", f"out:{dst}", "outbound", n, sev)

    weight = {x: len(ns) for x, ns in touched.items()}

    ahead = graph_engine.look_ahead(incident)
    shown = set(kind) | set(display.values())
    next_targets = [a for a in ahead if a["target"] not in shown]

    def members(k):
        return sorted((x for x in kind if kind[x] == k), key=lambda x: (-weight[x], x))

    columns = {
        "inbound": ("Came from", members("inbound")),
        "account": ("Accounts used", members("account")),
        "host": ("Compromised machines", members("host")),
        "outbound": ("Talked to", members("outbound")),
    }

    # Fold overflow nodes and redirect their edges to the "+N more" node.
    alias = {}
    for key, (_, members) in columns.items():
        if len(members) > GRAPH_COLUMN_CAP:
            more = f"+{len(members) - GRAPH_COLUMN_CAP + 1} more"
            for m in members[GRAPH_COLUMN_CAP - 1:]:
                alias[m] = f"{key}:{more}"
            columns[key] = (columns[key][0], members[:GRAPH_COLUMN_CAP - 1] + [f"{key}:{more}"])

    merged, merged_sev = {}, {}
    for (a, b), ns in edges.items():
        a2, b2 = alias.get(a, a), alias.get(b, b)
        merged.setdefault((a2, b2), []).extend(ns)
        merged_sev[(a2, b2)] = max(merged_sev.get((a2, b2), 0), severity[(a, b)])

    ext = f'shape=diamond style="filled" fillcolor="{COLOR_EXTERNAL}" fontcolor="white"'
    style = {
        "inbound": ext,
        "outbound": ext,
        "account": f'shape=ellipse style="filled" fillcolor="{COLOR_COMPROMISED}" fontcolor="white"',
        "host": f'shape=box style="rounded,filled" fillcolor="{COLOR_COMPROMISED}" fontcolor="white"',
    }

    lines = [
        "digraph G {",
        '  rankdir=LR; bgcolor="transparent"; nodesep=0.35; ranksep=1.1;',
        '  node [fontname="Helvetica" fontsize=11 margin="0.15,0.06" penwidth=0];',
        '  edge [fontname="Helvetica" fontsize=10 color="#868e96" fontcolor="#868e96" arrowsize=0.7];',
        '  graph [fontname="Helvetica" fontsize=12 fontcolor="#868e96" '
        'style="rounded,dashed" color="#ced4da" labeljust="l"];',
    ]
    for key, (title, members) in columns.items():
        if not members:
            continue
        lines.append(f'  subgraph "cluster_{key}" {{ label="{title}";')
        for m in members:
            overflow = m.startswith(f"{key}:+")
            label = m.split(":", 1)[1] if overflow else display[m]
            sub = "" if overflow else f"\\n{weight[m]} step{'s' if weight[m] != 1 else ''}"
            lines.append(f'    "{_dot(m)}" [label="{_dot(label)}{sub}" {style[key]}];')
        lines.append("  }")

    if next_targets:
        top = next_targets[:GRAPH_COLUMN_CAP - 1]
        rest = len(next_targets) - len(top)
        lines.append('  subgraph "cluster_next" { label="Reachable next";')
        for a in top:
            role = f"\\n{_dot(a['role'])}" if a.get("role") else ""
            crit = f" · crit {a['criticality']}" if a["criticality"] else ""
            lines.append(f'    "{_dot(a["target"])}" [label="{_dot(a["target"])}{role}{crit}" '
                         f'shape=box style="rounded,filled,dashed" fillcolor="{COLOR_AT_RISK}" '
                         f'fontcolor="white"];')
        if rest:
            lines.append(f'    "next:more" [label="+{rest} more" shape=box style="rounded,filled" '
                         f'fillcolor="{COLOR_AT_RISK}" fontcolor="white"];')
        lines.append("  }")
        # Pin the column to the right of the compromised machines, even for
        # targets reachable only through an account that is not drawn.
        anchor = next(iter(columns["host"][1]), None)
        for a in top + ([{"target": "next:more"}] if rest else []):
            via = next((alias.get(v, v) for v in (a.get("reachable_via") or [])
                        if v in kind), None)
            if via:
                lines.append(f'  "{_dot(via)}" -> "{_dot(a["target"])}" '
                             f'[style=dashed color="{COLOR_AT_RISK}" arrowhead=empty];')
            elif anchor:
                lines.append(f'  "{_dot(anchor)}" -> "{_dot(a["target"])}" [style=invis];')

    for (a, b), ns in merged.items():
        sev = merged_sev[(a, b)]
        width = 2.2 if sev >= 9 else 1.4 if sev >= 7 else 0.9
        colour = COLOR_COMPROMISED if sev >= 9 else "#868e96"
        lines.append(f'  "{_dot(a)}" -> "{_dot(b)}" [label=" {_step_ranges(ns)} " '
                     f'penwidth={width} color="{colour}"];')
    lines.append("}")
    hidden = 0 if show_context else \
        sum(1 for e in incident["events"] if e.get("context") == "host")
    return "\n".join(lines), hidden


def render_graph(incident):
    """Draw the attack graph (FR-5). Graphviz ships with Streamlit: no extra widget."""
    show_context = False
    if any(e.get("context") == "host" for e in incident["events"]):
        show_context = st.toggle("Show other accounts' alerts on the same machines",
                                 value=False, key=f"ctx_{incident['id']}")
    dot, hidden = build_attack_dot(incident, show_context)
    st.graphviz_chart(dot, width="stretch")
    if hidden:
        st.caption(f"{hidden} alert(s) hidden: other accounts active on the same "
                   f"machine within {graph_engine.HOST_CONTEXT_MINUTES} minutes. "
                   f"They are in the Timeline tab.")


@st.cache_data(show_spinner=False, max_entries=64)
def cached_raw_lines(log_path, log_mtime, db_path, incident_id, _incident):
    # Keyed on the file, its mtime and the incident; a second click is instant.
    from chronopath2 import link_evidence
    return link_evidence.fetch_raw_lines(log_path, _incident)


# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
st.markdown(
    "<div class='cp-masthead'><span class='cp-name'>ChronoPath</span>"
    "<span class='cp-tag'>Kill chain and attack path analysis</span></div>"
    f"<div class='cp-subline'>CyberForge 2026 &nbsp;·&nbsp; "
    f"data set: {html.escape(os.path.basename(DB_PATH))}</div>",
    unsafe_allow_html=True)

with st.sidebar:
    st.header("Pipeline")

    # Which database the page shows. Listed from the folder, so whatever was
    # built -- here or on the command line -- can be opened.
    dbs = _available_databases()
    if dbs:
        names = [os.path.basename(p) for p in dbs]
        current = os.path.basename(DB_PATH)
        picked = st.selectbox(
            "Database", names,
            index=names.index(current) if current in names else 0,
            help="Each log file gets its own database. Run detection below "
                 "builds one and switches to it.")
        if os.path.join(PROJECT_ROOT, picked) != DB_PATH:
            st.session_state["db_path"] = os.path.join(PROJECT_ROOT, picked)
            st.rerun()

    # Default the box to the log this database was actually built from, so the
    # two never silently disagree.
    shown_source = guess_source_log() if os.path.exists(DB_PATH) else None
    default_log = (os.path.relpath(shown_source, PROJECT_ROOT)
                   if shown_source and os.path.exists(shown_source)
                   else "data/sample.ndjson")
    log_file = st.text_input("Log file", value=default_log)

    if st.button("Run detection", width="stretch", type="primary"):
        log_path = log_file if os.path.isabs(log_file) else \
            os.path.join(PROJECT_ROOT, log_file)
        if not os.path.exists(log_path):
            st.error(f"Not found: {log_file}")
        else:
            # One database per log file, named after it, so a run never
            # overwrites another data set's results.
            stem = os.path.splitext(os.path.basename(log_path))[0]
            target_db = os.path.join(PROJECT_ROOT, f"{stem}.db")
            steps = [
                ("Streaming logs and applying rules...",
                 [sys.executable, os.path.join(PROJECT_ROOT, "src", "parser.py"),
                  "--input", log_path, "--db", target_db, "--no-cp2"]),
                # Without this the Evidence, What we can't see, Respond now and
                # Sources tabs stay empty.
                ("Building the evidence and gap layer...",
                 [sys.executable,
                  os.path.join(PROJECT_ROOT, "scripts", "run_cp2.py"),
                  "--db", target_db, "--input", log_path]),
            ]
            output, ok = [], True
            for label, cmd in steps:
                with st.spinner(label):
                    result = subprocess.run(
                        cmd, capture_output=True, text=True, cwd=PROJECT_ROOT,
                        encoding="utf-8", errors="replace",
                        env={**os.environ, "PYTHONIOENCODING": "utf-8"})
                output.append(result.stdout)
                if result.returncode != 0:
                    output.append(result.stderr)
                    ok = False
                    break
            st.session_state["last_run"] = {
                "ok": ok, "db": os.path.basename(target_db),
                "output": "\n".join(output)}
            if ok:
                st.session_state["db_path"] = target_db
                st.cache_data.clear()
                st.rerun()

    # Shown after the rerun that switched to the new database.
    last = st.session_state.get("last_run")
    if last:
        if last["ok"]:
            st.success(f"Detection complete — showing {last['db']}")
        else:
            st.error("Pipeline failed")
        st.code(last["output"][-1500:], language="text")

    st.divider()
    key_present = bool(os.environ.get("GROQ_API_KEY"))
    st.caption(f"Groq API key: {'detected ✅' if key_present else 'not set ⚠️'}")
    if not key_present:
        st.caption("Reports use a built-in summary. To enable the AI report, "
                   "create a file named `.env` next to README.md containing:")
        st.code("GROQ_API_KEY=gsk_your_key_here", language="text")
        st.caption("…then restart. Free key: console.groq.com")

    st.divider()
    st.caption("**Legend**")
    st.markdown(
        f"<span style='color:{COLOR_COMPROMISED}'>●</span> Compromised<br>"
        f"<span style='color:{COLOR_AT_RISK}'>●</span> Reachable next<br>"
        f"<span style='color:{COLOR_EXTERNAL}'>●</span> External IP<br>"
        f"<span style='color:{COLOR_CLEAN}'>●</span> Untouched",
        unsafe_allow_html=True)


if not os.path.exists(DB_PATH):
    st.info("No analysis yet. Set a log file in the sidebar and click "
            "**Run detection**.\n\nNo logs? Generate some first:\n\n"
            "```\npython scripts/generate_sample.py\n```")
    st.stop()

incidents = load_incidents(db_signature())

if not incidents:
    st.warning("No suspicious events detected in this data set.")
    st.stop()

# Incidents arrive pre-sorted worst-first (bonus B-1).
labels = [f"{i['id']} — risk {i['risk_score']}/100 ({i['detection_count']} steps)"
          for i in incidents]
choice = st.sidebar.selectbox("Incident", range(len(incidents)),
                              format_func=lambda i: labels[i])
incident = incidents[choice]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Risk score", f"{incident['risk_score']}/100")
c2.metric("Raw alerts merged", incident["raw_alert_count"])   # bonus B-3
c3.metric("Attack steps", incident["detection_count"])
c4.metric("Hosts involved", len(incident["hosts"]))

# Be transparent about noise suppression. Hiding low-confidence groups without
# saying so would leave an analyst unable to distinguish "nothing else found"
# from "something found and filtered".
suppressed = incidents[0].get("_suppressed_count", 0)
if suppressed:
    st.caption(
        f"ℹ️ {suppressed} low-confidence group(s) covering "
        f"{incidents[0].get('_suppressed_detections', 0)} detection(s) were "
        f"suppressed as noise (risk below {graph_engine.MIN_INCIDENT_RISK} and "
        f"fewer than {graph_engine.MIN_STEPS_TO_ALWAYS_REPORT} distinct techniques).")
blocked = incidents[0].get("_blocked_threat_count", 0)
if blocked:
    st.caption(
        f"🛡️ {blocked} blocked threat(s) covering "
        f"{incidents[0].get('_blocked_threat_detections', 0)} detection(s) are "
        f"not shown as incidents: every step was stopped by a control or shows "
        f"only an attempt (e.g. failed logins with no success).")
estate = incidents[0].get("_estate_wide") or []
if estate:
    with st.expander(f"Estate-wide activity ({len(estate)} technique(s) "
                     f"seen across most machines or accounts)"):
        st.dataframe([{
            "Technique": s["technique"], "Name": s["technique_name"],
            "Machines": s["hosts"], "Accounts": s["accounts"],
            "Detections": s["detections"], "Allowed through": s["allowed"],
        } for s in estate], width="stretch", hide_index=True)

st.divider()

# Tab order follows the order an analyst actually works, which is why the 2.0
# tabs are interleaved rather than appended: understand the incident, check the
# evidence behind it, find out what is missing, decide what to do, then hunt.
(tab_story, tab_investigator, tab_timeline, tab_graph, tab_evidence, tab_blind,
 tab_respond, tab_next, tab_hunt, tab_sources) = st.tabs(
    ["Report", "Investigator", "Timeline", "Attack graph", "Evidence",
     "What we can't see", "Respond now", "What's next",
     "Threat hunting", "Sources"])

with tab_investigator:
    # The Elliot reasoning layer: reads what ChronoPath established, questions
    # it, and proposes what to check next. See src/elliot/.
    elliot_ui.render(DB_PATH, incident)

with tab_story:
    st.subheader("Incident report")
    links = cp2_read(
        db_signature(),
        "SELECT grade, reason FROM cp2_links WHERE incident_id = ? "
        "ORDER BY time_delta_s", [incident["id"]])
    summary = graph_engine.summarise_for_llm(incident, links)
    report, status = generate_report(summary, incident["id"])

    if status == "ok":
        st.markdown(report)
        st.caption("Written by GPT-OSS 120B via Groq from the structured attack path.")
    else:
        st.markdown(fallback_report(incident))
        if status == "no_key":
            st.caption("ℹ️ Built-in summary. Set GROQ_API_KEY for the AI-written version.")
        else:
            st.caption(f"⚠️ Groq unavailable, showing built-in summary. ({report[:120]})")

    with st.expander("Structured data sent to the model"):
        st.code(summary, language="text")

with tab_timeline:
    st.subheader("Attack timeline")
    st.caption("Chronological order — this is what turns separate alerts into a kill chain.")
    rows = []
    for s in graph_engine.get_attack_path(incident):
        rows.append({
            "#": s["step"],
            "Time": s["timestamp"][:19].replace("T", " "),
            "Kill chain stage": s["stage"],
            "ATT&CK": f"{s['technique']} {s['technique_name']}",
            "Detection": s["rule"],
            "Host": s["host"],
            "Account": s["user"],
            "Sev": s["severity"],
        })
    st.dataframe(rows, width="stretch", hide_index=True)

with tab_graph:
    st.subheader("Attack path graph")
    st.caption("Read left to right. Numbers on arrows are step numbers from the "
               "Timeline tab; thick red arrows are severity 9+. Dashed amber "
               "boxes are reachable next but not yet touched.")
    render_graph(incident)

with tab_next:
    st.subheader("What the attacker could reach next")
    ahead = graph_engine.look_ahead(incident)
    if not ahead:
        st.success("No further systems reachable from the observed activity.")
    else:
        crits = [a for a in ahead if a["criticality"] >= 9]
        if crits:
            names = ", ".join(a["target"] for a in crits)
            st.error(f"🚨 Critical systems within reach: **{names}**")
        st.caption("Sorted by criticality. 'privilege' means standing admin rights "
                   "from the identity inventory; 'observed' means a path already "
                   "seen in the logs.")
        st.dataframe(
            [{"Target": a["target"],
              "Role": a["role"] or "-",
              # One type per column: mixing ints with "-" fails Arrow conversion.
              "Criticality": str(a["criticality"]) if a["criticality"] else "-",
              "Basis": a["basis"],
              "Why": a["reason"]} for a in ahead],
            width="stretch", hide_index=True)

with tab_hunt:
    # THREAT HUNTING -- the inverse of every other tab.
    #
    # The rest of the dashboard answers "here is the attack our rules found".
    # This answers "here is what looks statistically odd, go and look" -- and
    # it needs no rule to know in advance what an attack looks like. Inspired
    # by Hayabusa's pivot-keywords-list, but ranked automatically because on
    # 9 million events nobody can eyeball a list.
    st.subheader("Pivot points — what looks anomalous")
    st.caption("Ranked by rarity, severity and kill-chain spread. Attackers "
               "touch few things; routine noise touches many. **No detection "
               "rule is involved here** — this finds odd entities on "
               "statistics alone, including attacks nobody wrote a rule for.")

    try:
        import pivot as pivot_mod
        ranked = pivot_mod.rank_entities(DB_PATH, top_n=8)
        buckets = pivot_mod.activity_timeline(DB_PATH)
    except Exception as exc:
        ranked, buckets = {}, []
        st.warning(f"Pivot analysis unavailable: {exc}")

    if buckets:
        st.markdown("**Detections over time** — attacks usually arrive in bursts.")
        st.bar_chart(
            {b["hour"]: b["detections"] for b in buckets},
            height=180, width="stretch")
        busiest = max(buckets, key=lambda b: b["detections"])
        st.caption(f"Busiest hour: **{busiest['hour']}** with "
                   f"{busiest['detections']:,} detections.")

    for kind in ("Users", "Source IPs", "Hosts", "Processes"):
        if kind not in ranked or not ranked[kind]:
            continue
        st.markdown(f"**{kind}**")
        st.dataframe(
            [{"Anomaly": e["anomaly_score"],
              "Value": e["value"],
              "Events": e["event_count"],
              "Worst severity": e["max_severity"],
              "Kill chain stages": ", ".join(e["kill_chain_stages"]) or "-"}
             for e in ranked[kind]],
            width="stretch", hide_index=True)


# ===========================================================================
# ChronoPath 2.0 tabs
#
# WHY THESE FOUR EXIST, in the order an analyst needs them:
#
#   Evidence           "Why do you think these events belong together?"
#   What we can't see  "What couldn't you see, and what should I request?"
#   Respond now        "What do I do in the next ten minutes?"
#   Sources            "Can I trust the data underneath all of this?"
#
# Each is read-only over the cp2_ tables. Nothing here computes a finding --
# they display what scripts/run_cp2.py already derived and stored, which keeps
# the dashboard responsive on a 6.54 GB investigation and means the same facts
# reach the API and the terminal identically.
# ===========================================================================

GRADE_HELP = {
    "HARD": ("Strongest link available in any log: the same account acted in "
             "both events, or one event created the account that acted in the "
             "other. An account is the actor."),
    "SOFT": ("Good evidence, not conclusive: a shared external address or a "
             "shared machine inside the window. An address can be a VPN exit "
             "or a NAT gateway used by unrelated people."),
    "INFERRED": ("Context, not proof: attached by machine alone within 15 "
                 "minutes, with no shared account or address."),
    "UNRESOLVED": ("A candidate link that was REJECTED -- shared "
                   "infrastructure or a placeholder value. Shown so the "
                   "refusal is visible rather than silent."),
}
GRADE_COLOR = {"HARD": "#2e7d32", "SOFT": "#f9a825",
               "INFERRED": "#757575", "UNRESOLVED": "#c62828"}

CLASS_STYLE = {
    "LOGGING_DISABLED_BY_ACTOR": (
        "[!]", "An actor disabled logging AND telemetry measurably stopped."),
    "LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA": (
        "[~]", "Logging was disabled, but this file kept recording -- so it is "
               "likely a forwarded copy and the window is still visible."),
    "NOT_COLLECTED": (
        "[ ]", "This telemetry is not present in any supplied source. A fact "
               "about our inputs, not evidence of destruction."),
    "PARSE_FAILURE": (
        "[?]", "Rows the reader could not use, or timestamps it could not "
               "parse."),
    "COVERAGE_UNKNOWN": (
        "[-]", "We cannot tell whether this was collected. Not a claim that "
               "it expired."),
}


with tab_evidence:
    st.subheader("Why these events belong together")
    st.caption(
        "Union-find grouped these detections because they shared an entity "
        "inside a time window. That is an algorithm, not an explanation. Every "
        "link below carries the attribute it rests on, how far apart the "
        "events were, a grade for how good that evidence is, and the original "
        "log line."
    )

    if not CP2_AVAILABLE:
        st.warning("The chronopath2 package could not be imported.")
    elif not cp2_has_data(db_signature()):
        cp2_missing_notice("cp2_build_1")
    else:
        sig = db_signature()
        links = cp2_read(
            sig,
            "SELECT * FROM cp2_links WHERE incident_id = ? "
            "ORDER BY CASE grade WHEN 'HARD' THEN 1 WHEN 'SOFT' THEN 2 "
            "WHEN 'INFERRED' THEN 3 ELSE 4 END, time_delta_s",
            [incident["id"]])

        if not links:
            # A single-detection incident has no pairs to link. Saying so
            # explicitly beats an empty table, which reads as a failure.
            st.info(
                f"**{incident['id']} holds a single detection**, so there is "
                f"no link to explain -- there is no second event to connect it "
                f"to. It was reported on its own merit: a maximum-severity "
                f"rule fired, and rare unambiguous signals are always reported "
                f"however isolated. The separation statements below show what "
                f"was checked against the other incidents."
            )
        else:
            counts = {}
            for row in links:
                counts[row["grade"]] = counts.get(row["grade"], 0) + 1
            metric_cols = st.columns(len(counts) or 1)
            for col, (grade, n) in zip(metric_cols, sorted(counts.items())):
                col.metric(f"{grade} links", n)

            for row in links:
                colour = GRADE_COLOR.get(row["grade"], "#555555")
                mins = row["time_delta_s"] / 60.0
                with st.expander(
                        f"{row['grade']}  .  {row['link_attribute']} = "
                        f"{row['attribute_value']}  .  {mins:.0f} min apart",
                        expanded=(row["grade"] == "HARD")):
                    st.markdown(
                        f"<span style='color:{colour};font-weight:600'>"
                        f"{row['grade']}</span> &mdash; "
                        f"{GRADE_HELP.get(row['grade'], '')}",
                        unsafe_allow_html=True)
                    st.markdown(f"**Why:** {row['reason']}")
                    st.caption(
                        f"{row['event_a']}  <->  {row['event_b']}  .  "
                        f"{row['time_delta_s']:,}s apart, within a "
                        f"{row['window_s']:,}s window")

        # Rejected candidate links -- the section most tools omit, and where an
        # analyst should be able to overrule us.
        rejected = cp2_read(
            db_signature(),
            "SELECT * FROM cp2_rejected_links WHERE incident_id = ?",
            [incident["id"]])
        if rejected:
            st.divider()
            st.markdown("#### Links we deliberately refused")
            st.caption(
                "Silent refusal is its own trap: an analyst cannot tell "
                "'genuinely unrelated' from 'the tool decided not to connect "
                "them and did not say'. These are the candidate links the "
                "engine rejected, with the counts that triggered the refusal."
            )
            for row in rejected:
                st.markdown(
                    f"- **{row['attribute_value']}** "
                    f"({row['link_attribute']}, {row['event_count']} events) "
                    f"&mdash; {row['reason']}")

        # Raw log lines, fetched on demand. Storing them for all 9.1 M rows
        # would be a second copy of a 6.54 GB file to serve a few lookups.
        st.divider()
        st.markdown("#### Original log lines")
        st.caption(
            "A real investigation ends at the raw record. These are read from "
            "the source file on request, for this incident only."
        )
        log_for_raw = st.text_input(
            "Source log file",
            value=st.session_state.get(
                f"cp2_log_path:{DB_PATH}",
                guess_source_log() or "D:/firex-10G.log"),
            key=f"cp2_raw_log:{DB_PATH}")
        if st.button("Fetch raw lines for this incident"):
            st.session_state[f"cp2_log_path:{DB_PATH}"] = log_for_raw
            if not os.path.exists(log_for_raw):
                st.error(f"Not found: {log_for_raw}")
            else:
                with st.spinner("Scanning the source file (large files take "
                                "up to about 30 s)..."):
                    raw_lines = cached_raw_lines(
                        log_for_raw, os.path.getmtime(log_for_raw),
                        DB_PATH, incident["id"], incident)
                if raw_lines:
                    st.success(f"{len(raw_lines)} line(s) found")
                    for raw in raw_lines:
                        st.code(raw, language="text")
                else:
                    st.warning(
                        "No matching lines found. These detections may come "
                        "from a different file than the one named above.")

        # Why the incidents are separate. The honest form of a five-incident
        # result on data whose actors genuinely share nothing.
        sep = cp2_read(
            db_signature(),
            "SELECT * FROM cp2_incident_separation "
            "WHERE incident_a = ? OR incident_b = ? ORDER BY 1, 2",
            [incident["id"], incident["id"]])
        if sep:
            st.divider()
            st.markdown(f"#### Why {incident['id']} is separate from the others")
            st.caption(
                "Reporting several incidents is itself a claim. These state "
                "what was compared, so the claim can be checked rather than "
                "trusted."
            )
            icons = {"NO_SHARED_ENTITY": "[ok]",
                     "SEPARATED_BY_INFRASTRUCTURE_CUTOFF": "[infra]",
                     "SEPARATED_BY_TIME": "[time]",
                     "SHARED_ENTITY_PRESENT": "[!]"}
            for row in sep:
                other = (row["incident_b"]
                         if row["incident_a"] == incident["id"]
                         else row["incident_a"])
                with st.expander(
                        f"{icons.get(row['verdict'], '.')} vs {other} "
                        f"&mdash; {row['verdict']}"):
                    st.markdown(row["statement"])
                    st.caption(
                        f"shared accounts: {row['shared_accounts']}  .  "
                        f"shared external IPs: {row['shared_ips']}  .  "
                        f"rejected values: {row['shared_rejected']}")


with tab_blind:
    st.subheader("What we can't see")
    st.caption(
        "Every detection tool reports what it found. Almost none report what "
        "they could not have found, and silence reads as 'nothing happened'. "
        "Each gap below carries the facts that establish it, what it prevents "
        "you concluding, and the evidence that would close it."
    )

    if not CP2_AVAILABLE:
        st.warning("The chronopath2 package could not be imported.")
    elif not cp2_has_data(db_signature()):
        cp2_missing_notice("cp2_build_2")
    else:
        sig = db_signature()

        st.info(
            "**Missing is not malicious.** Absent logs are classified "
            "NOT_COLLECTED or COVERAGE_UNKNOWN, never as deletion, unless a "
            "positive event proves otherwise. Logs go missing for mundane "
            "reasons far more often than malicious ones: the agent was never "
            "installed, the forwarder was down, nobody licensed that source."
        )

        own = cp2_read(sig,
                       "SELECT * FROM cp2_gaps WHERE incident_id = ? "
                       "ORDER BY classification, gap_id", [incident["id"]])
        st.markdown(f"#### Gaps affecting {incident['id']}")
        if not own:
            st.success("No incident-specific gaps recorded.")
        for row in own:
            icon, meaning = CLASS_STYLE.get(row["classification"], (".", ""))
            with st.expander(
                    f"{icon} {row['classification']} &mdash; "
                    f"{row['telemetry']} ({row['asset_or_entity']})",
                    expanded=True):
                st.caption(meaning)
                st.markdown(f"**What establishes this:** {row['basis']}")
                st.markdown(
                    f"**What you therefore cannot conclude:** {row['impact']}")
                st.markdown(f"**Request next:** {row['evidence_request']}")
                if row["time_start"] or row["time_end"]:
                    st.caption(
                        f"window: {row['time_start'] or 'before the file'} "
                        f"-> {row['time_end'] or 'end of data'}")

        glob = cp2_read(sig,
                        "SELECT * FROM cp2_gaps WHERE incident_id = 'GLOBAL' "
                        "ORDER BY classification, gap_id")
        if glob:
            st.divider()
            st.markdown("#### Estate-wide gaps")
            st.caption("Properties of the supplied data rather than of any one "
                       "incident.")
            for row in glob:
                icon, meaning = CLASS_STYLE.get(row["classification"], (".", ""))
                with st.expander(f"{icon} {row['classification']} &mdash; "
                                 f"{row['telemetry']}"):
                    st.caption(meaning)
                    st.markdown(f"**What establishes this:** {row['basis']}")
                    st.markdown(
                        f"**What you therefore cannot conclude:** "
                        f"{row['impact']}")
                    st.markdown(f"**Request next:** {row['evidence_request']}")

        # The blind window against measured volume. Shading the window is the
        # clearest way to show whether anything actually stopped arriving.
        blind = [row for row in own
                 if row["classification"].startswith("LOGGING_DISABLED")]
        if blind:
            st.divider()
            st.markdown("#### The blind window, against measured log volume")
            for row in blind:
                st.markdown(f"**{row['time_start']} -> {row['time_end']}** "
                            f"({row['classification']})")
                wider = cp2_read(
                    sig,
                    "SELECT hour_bucket, SUM(event_count) AS events "
                    "FROM cp2_stream_volume GROUP BY 1 ORDER BY 1")
                if wider:
                    start_s = str(row["time_start"])
                    end_s = str(row["time_end"])
                    chart = []
                    for v in wider:
                        hb = str(v["hour_bucket"])
                        inside = start_s[:13] <= hb[:13] <= end_s[:13]
                        chart.append({
                            "hour": hb,
                            "events": v["events"],
                            "in blind window": v["events"] if inside else 0,
                        })
                    st.caption(
                        "The second series marks the window. If it reaches the "
                        "same height as the first, nothing stopped arriving."
                    )
                    st.bar_chart(chart, x="hour",
                                 y=["events", "in blind window"])


with tab_respond:
    st.subheader("Respond now")
    st.caption(
        "Indicators, whether it is still happening, what preceded it, and "
        "recommended containment. Every indicator is looked up across the "
        "whole data set rather than inside the incident -- an incident's end "
        "time is the last time these detections fired, not the last time the "
        "attacker was seen."
    )

    if not CP2_AVAILABLE:
        st.warning("The chronopath2 package could not be imported.")
    elif not cp2_has_data(db_signature()):
        cp2_missing_notice("cp2_build_3")
    else:
        sig = db_signature()
        inds = cp2_read(sig,
                        "SELECT * FROM cp2_indicators WHERE incident_id = ? "
                        "ORDER BY indicator_type, value", [incident["id"]])

        st.markdown("#### Indicators")
        if inds:
            st.dataframe(
                [{"Type": row["indicator_type"],
                  "Value": row["value"],
                  "First seen (whole data set)": row["first_seen"],
                  "Last seen (whole data set)": row["last_seen"],
                  "Detections": row["occurrences"],
                  "Note": row["note"] or ""} for row in inds],
                width="stretch", hide_index=True)

            still = [row for row in inds
                     if (row["note"] or "").startswith("STILL ACTIVE")]
            if still:
                st.error(
                    f"**{len(still)} indicator(s) were seen AFTER this "
                    f"incident's last event. This is not over:** "
                    + ", ".join(row["value"] for row in still))
            else:
                st.success(
                    "No indicator from this incident appears after its last "
                    "event anywhere in the supplied data. Nothing here "
                    "suggests the activity continued -- within the limits of "
                    "what we were given."
                )

            st.text_area("Copyable indicator list",
                         "\n".join(row["value"] for row in inds), height=110)
        else:
            st.info("No indicators recorded for this incident.")

        # Preceding access: how did they get in?
        st.divider()
        st.markdown("#### What preceded the first detection")
        ledger = cp2_read(sig,
                          "SELECT * FROM cp2_gaps WHERE incident_id = ?",
                          [incident["id"]])
        pre_con = duckdb.connect(DB_PATH, read_only=True)
        try:
            pre = cp2_respond.preceding_access(
                pre_con, incident, parse_ts=graph_engine._parse_ts)
        finally:
            pre_con.close()
        st.markdown(pre["summary"])
        if pre["rows"]:
            st.dataframe(
                [{"Time": row["timestamp"], "Account": row["user"],
                  "Source IP": row["src_ip"], "Rule": row["rule_name"],
                  "Technique": row["mitre_technique"],
                  "Outcome": row["outcome"], "Raw events": row["raw"]}
                 for row in pre["rows"][:60]],
                width="stretch", hide_index=True)

        # Recommended actions.
        st.divider()
        st.markdown("#### Recommended actions")
        st.caption(
            "Rule-based, selected by conditions observed in the data -- not "
            "written by the language model. Containment advice should not "
            "vanish when an API key expires, and should not be improvised by a "
            "model when someone may run it on production infrastructure. "
            "**Nothing here has been done or automated.**"
        )
        actions = cp2_respond.suggested_actions(incident, ledger)
        order = {"immediate": 0, "high": 1, "standard": 2, "follow-up": 3}
        badges = {"immediate": "IMMEDIATE", "high": "HIGH",
                  "standard": "STANDARD", "follow-up": "FOLLOW-UP"}
        for act in sorted(actions, key=lambda a: order.get(a["priority"], 9)):
            with st.expander(
                    f"[{badges.get(act['priority'], act['priority'])}] "
                    f"{act['observation']}", expanded=True):
                st.caption(f"Status: **{act['status']}** -- nothing automated")
                for step in act["steps"]:
                    st.markdown(f"- {step}")


with tab_sources:
    st.subheader("Can I trust this data?")
    st.caption(
        "Provenance and coverage for every input. The first question about any "
        "finding is whether the data underneath it is sound; without this the "
        "answer is unfalsifiable."
    )

    if not CP2_AVAILABLE:
        st.warning("The chronopath2 package could not be imported.")
    else:
        sig = db_signature()
        fps = cp2_read(sig,
                       "SELECT * FROM cp2_source_fingerprint "
                       "ORDER BY recorded_at")
        if not fps:
            st.info(
                "No coverage pass has been run for this database. Run:\n\n"
                f"```\npython scripts/build_coverage.py --input <log> --db "
                f"{os.path.basename(DB_PATH)}\n```")
            build_cp2_now("cp2_build_sources")
        for fp in fps:
            st.markdown(f"#### {fp['source']}")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Format", fp["detected_format"])
            c2.metric("Events", f"{fp['total_rows']:,}")
            c3.metric("Streams", fp["streams_found"])
            c4.metric("Size", f"{(fp['size_bytes'] or 0) / 1024 ** 3:.2f} GB")

            st.caption(f"**Time range:** {fp['earliest_ts']} -> "
                       f"{fp['latest_ts']}")
            st.caption(f"**Timestamp field used:** {fp['timestamp_field']}")
            st.caption(f"**SHA-256:** `{fp['sha256']}`")
            st.caption(
                "The digest pins the exact bytes these findings came from. A "
                "filename is not reproducible; a hash is.")

            bad = int(fp["bad_timestamp_rows"] or 0)
            rej = int(fp["rejected_rows"] or 0)
            if bad or rej:
                st.warning(
                    f"{rej:,} row(s) rejected and {bad:,} with an unparseable "
                    f"timestamp. These are flagged, not silently sorted to the "
                    f"start of the timeline -- see the gap ledger.")
            else:
                st.success(
                    "Every row was read and carried a parseable timestamp.")

            # The clock note. This single field is what prevents a silent
            # five-and-a-half-hour error on the organisers' data.
            st.info(f"**Clock check:** {fp['clock_note']}")

            rows = cp2_read(sig,
                            "SELECT stream, SUM(event_count) AS events, "
                            "MIN(hour_bucket) AS first_hour, "
                            "MAX(hour_bucket) AS last_hour, "
                            "COUNT(*) AS active_hours "
                            "FROM cp2_stream_volume WHERE source = ? "
                            "GROUP BY 1 ORDER BY events DESC", [fp["source"]])
            if rows:
                total = sum(r["events"] for r in rows) or 1
                st.markdown("**Telemetry streams**")
                st.caption(
                    "A FortiGate log is not one source -- it multiplexes "
                    "independent subsystems, each with its own coverage. That "
                    "is what makes a per-stream outage visible even from a "
                    "single supplied file."
                )
                st.dataframe(
                    [{"Stream": r["stream"],
                      "Events": f"{r['events']:,}",
                      "Share": f"{r['events'] / total * 100:.2f}%",
                      "Active hours": r["active_hours"],
                      "First": str(r["first_hour"]),
                      "Last": str(r["last_hour"])} for r in rows],
                    width="stretch", hide_index=True)

                vol = cp2_read(sig,
                               "SELECT hour_bucket, SUM(event_count) AS events "
                               "FROM cp2_stream_volume WHERE source = ? "
                               "GROUP BY 1 ORDER BY 1", [fp["source"]])
                if vol:
                    st.markdown("**Event volume over the whole file**")
                    st.caption("A steady line means steady collection. A cliff "
                               "means something stopped sending.")
                    st.bar_chart(
                        [{"hour": str(v["hour_bucket"]), "events": v["events"]}
                         for v in vol], x="hour", y="events")

# Site footer, last on the page.
st.markdown(
    "<div class='cp-footer'>ChronoPath &nbsp;·&nbsp; kill chain and attack path "
    "analysis &nbsp;·&nbsp; CyberForge 2026</div>",
    unsafe_allow_html=True)
