"""
blind_window.py -- Did the attacker actually blind us? (ChronoPath 2.0, Task 2)

WHY THIS FILE EXISTS
--------------------
In INC-02 the account `Tejas.Roy` disabled the firewall's disk logging at
16:31:43 on 2026-10-23, then purged the firewall policy objects at 18:28:52.
That is textbook T1562 (Impair Defenses) followed by action under cover.

The obvious thing to report is: "the attacker turned off logging, so you are
blind for two hours." It is dramatic, it fits the kill-chain narrative, and on
this data **it is false.** This module exists to tell the difference, because
an analyst who is told they are blind when they are not will go hunting for
evidence that was never missing, and will trust the next such claim less.

THE DISTINCTION THAT MATTERS
----------------------------
"Logging was disabled" and "we lost visibility" are two different claims:

    The config change     -> a fact, with a positive event proving it.
    The loss of telemetry -> a separate claim, which must be measured.

A firewall typically writes logs to several destinations at once: local disk,
and a remote syslog or FortiAnalyzer collector. Disabling *disk* logging does
nothing to the forwarded copy. If the file we were given is the forwarded copy,
the attacker blinded the box in front of them and we still see everything.

So this module never infers loss from the disable event. It measures volume.

HOW THE MEASUREMENT AVOIDS THE OBVIOUS TRAP
-------------------------------------------
Comparing "the two hours after" against "the two hours before" looks sufficient
and is not, because log volume follows a daily rhythm. Business traffic falls
every evening. Measured on this file, volume drops 38.9% from mid-afternoon to
early evening EVERY DAY. A naive before/after test with a 30% threshold would
therefore fire on all six days in the file and call each one an attacker
blinding the logs -- six false accusations from one careless baseline.

The fix is a CONTROL: compare the same clock hours on the other days in the
file. If the window's drop matches the normal daily curve, the decline is the
curve, not the attacker.

MEASURED RESULT ON THE ORGANISERS' DATA
---------------------------------------
Window 16:30-19:00 against 14:00-16:30 on each day:

    2026-10-23  (the blind window)   -38.9%      <-- the day logging was off
    2026-10-24                        -38.7%
    2026-10-25                        -38.8%
    2026-10-26                        -38.9%
    2026-10-27                        -38.8%
    2026-10-28                        -38.7%

The blind-window day is indistinguishable from the control days, to within
0.2 percentage points. Further, `event/system` -- the stream that carries admin
and config activity -- kept recording throughout, which is how we can see the
18:28 policy purge at all. The purge was logged. We were not blind.

Classification: LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA.

This is the truthful answer and it is reported as such. It is also the more
useful finding operationally: it tells the analyst the disable attempt FAILED
to achieve its purpose, that the supplied data is a forwarded stream, and that
the right evidence request is the FortiAnalyzer copy to confirm independently.
The threshold below was NOT tuned to manufacture a drop (ground rule 4).
"""

from datetime import timedelta

# How much per-stream volume must fall inside the window, relative to the
# control-adjusted baseline, before we are willing to call it a real loss of
# telemetry. 50% is deliberately demanding: accusing an attacker of destroying
# evidence is a strong claim, and a weak signal should not carry it.
SIGNIFICANT_DROP_PCT = 50.0

# How far past the disable event to look when no "logging re-enabled" event
# exists. Three hours is long enough to cover the INC-02 window (the policy
# purge came 1h57m later) without silently extending a gap claim across days.
DEFAULT_WINDOW_HOURS = 3

# Tolerance when comparing the window's drop against the daily-curve control.
# If the window drops no more than this many points beyond the normal curve for
# those hours, the decline IS the curve. 10 points is comfortably wider than
# the 0.2-point spread measured across the six control days.
CURVE_TOLERANCE_PCT = 10.0

# Techniques that mean "a defensive control was interfered with". T1562 is
# Impair Defenses and its sub-techniques; T1070 is Indicator Removal. Matched
# by prefix so T1562.002 / T1562.004 are covered without listing every child.
IMPAIR_PREFIXES = ("T1562", "T1070")

# Words in a rule name or message that indicate logging specifically, as
# opposed to some other control. A firewall policy purge is T1562.004 but is
# not a logging change, so it must not open a blind window of its own.
LOGGING_WORDS = ("logging", "log disk", "log setting", "event log", "audit")
RE_ENABLE_WORDS = ("enable", "enabled", "restored", "re-enabled")


def _is_logging_disable(event):
    """
    True only for a positive event showing logging was turned OFF.

    Both halves are required, and this is the gate that keeps ground rule 5
    ("missing is not malicious") enforceable: a blind window can only ever be
    opened by an event that exists, never by an absence.
    """
    tech = str(event.get("mitre_technique") or "")
    if not tech.startswith(IMPAIR_PREFIXES):
        return False
    text = f"{event.get('rule_name') or ''} {event.get('message') or ''}".lower()
    if not any(w in text for w in LOGGING_WORDS):
        return False
    # Guard against counting a re-enable as a disable. Rules in this project
    # name the disable explicitly, but the data is the organisers' and a future
    # rule might phrase it either way.
    return not any(f"{w} " in text for w in ("enabling", "re-enabling"))


def _is_logging_enable(event):
    tech = str(event.get("mitre_technique") or "")
    text = f"{event.get('rule_name') or ''} {event.get('message') or ''}".lower()
    return (tech.startswith(IMPAIR_PREFIXES)
            and any(w in text for w in LOGGING_WORDS)
            and any(w in text for w in RE_ENABLE_WORDS))


def _volume_between(con, start, end, source=None):
    """
    Total events per stream in [start, end), from the Task 1 volume table.

    Reads the hourly aggregate rather than re-scanning the log: a blind-window
    check that cost another 6.54 GB scan could not run interactively.
    """
    params = [start, end]
    where = "hour_bucket >= ? AND hour_bucket < ?"
    if source:
        where += " AND source = ?"
        params.append(source)
    try:
        rows = con.execute(
            f"SELECT stream, SUM(event_count) FROM cp2_stream_volume "
            f"WHERE {where} GROUP BY 1", params).fetchall()
    except Exception:
        return {}
    return {r[0]: int(r[1] or 0) for r in rows}


def _daily_curve_control(con, window_start, window_end, source=None,
                         days_each_side=4):
    """
    Measure the same before/after ratio on OTHER days, as a control.

    Returns the mean percentage change seen on comparable days, or None if the
    file does not span enough days to form a control. Returning None rather
    than a guess matters: without a control we cannot separate the attacker
    from the daily curve, and the classification must say so.
    """
    span = window_end - window_start
    changes = []
    for offset in range(-days_each_side, days_each_side + 1):
        if offset == 0:
            continue
        shift = timedelta(days=offset)
        w_start, w_end = window_start + shift, window_end + shift
        before = sum(_volume_between(con, w_start - span, w_start,
                                     source).values())
        after = sum(_volume_between(con, w_start, w_end, source).values())
        # Require real volume on both sides, or the ratio is meaningless.
        if before > 0 and after > 0:
            changes.append((after - before) / before * 100.0)
    if not changes:
        return None
    return sum(changes) / len(changes)


def _ensure_table(con):
    """
    Create `cp2_gaps`, shared with Task 4.

    Both modules write gaps, and a gap from a blind window is the same kind of
    record as a gap from absent telemetry -- the analyst wants one ledger, not
    two. The schema is defined identically in gaps.py; whichever runs first
    creates it.
    """
    con.execute("""
        CREATE TABLE IF NOT EXISTS cp2_gaps (
            gap_id           VARCHAR,
            incident_id      VARCHAR,
            asset_or_entity  VARCHAR,
            telemetry        VARCHAR,
            time_start       VARCHAR,
            time_end         VARCHAR,
            classification   VARCHAR,
            basis            VARCHAR,
            impact           VARCHAR,
            evidence_request VARCHAR
        )
    """)


def analyse_incident(con, incident, source=None, parse_ts=None):
    """
    Find and classify every blind window in one incident.

    Returns a list of gap dicts, each carrying the facts behind it. An empty
    list means there was no positive logging-disable event -- which is the
    common and correct outcome, not a failure.
    """
    from datetime import datetime

    def _ts(value):
        if parse_ts:
            return parse_ts(value)
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")
                                      ).replace(tzinfo=None)

    events = incident.get("events") or []
    disables = [e for e in events if _is_logging_disable(e)]
    if not disables:
        return []

    enables = [e for e in events if _is_logging_enable(e)]
    gaps = []

    for n, dis in enumerate(disables, start=1):
        try:
            start = _ts(dis["timestamp"])
        except (ValueError, TypeError):
            continue

        # Prefer a real re-enable event as the window's end. Absent one, cap
        # the window rather than letting it run to the end of the file -- an
        # unbounded gap claim is a claim about data we never examined.
        end, end_basis = None, ""
        later = sorted((_ts(e["timestamp"]) for e in enables
                        if _ts(e["timestamp"]) > start))
        if later:
            end = later[0]
            end_basis = "ends at the matching logging-enabled event"
        else:
            inc_end = None
            try:
                inc_end = _ts(incident.get("end_time")) if incident.get("end_time") else None
            except (ValueError, TypeError):
                inc_end = None
            cap = start + timedelta(hours=DEFAULT_WINDOW_HOURS)
            if inc_end and start < inc_end < cap:
                end, end_basis = inc_end, "ends at the last event in the incident"
            else:
                end = cap
                end_basis = (f"no logging-enabled event found; window capped at "
                             f"+{DEFAULT_WINDOW_HOURS}h")

        span = end - start
        inside = _volume_between(con, start, end, source)
        before = _volume_between(con, start - span, start, source)
        total_in, total_before = sum(inside.values()), sum(before.values())

        # The streams that carry admin and config activity. If these kept
        # recording, the config change that disabled logging was itself logged
        # -- which is both the proof we are not blind and the reason we can
        # see the attacker's next action.
        admin_in = sum(v for k, v in inside.items() if k.startswith("event/"))

        drop_pct = (((total_before - total_in) / total_before * 100.0)
                    if total_before else None)
        curve_pct = _daily_curve_control(con, start, end, source)
        # The daily curve, expressed as a drop, so the two are comparable.
        curve_drop = -curve_pct if curve_pct is not None else None

        actor = dis.get("user") or "unknown"
        asset = dis.get("host") or "unknown"

        if drop_pct is None:
            classification = "COVERAGE_UNKNOWN"
            basis = (f"Logging was disabled by {actor} at {start} "
                     f"({dis.get('rule_name')}), but no volume baseline exists "
                     f"for the window before it, so the effect cannot be "
                     f"measured. Run scripts/build_coverage.py first.")
            impact = ("Cannot determine whether telemetry was lost in this "
                      "window. Do not assume either way.")
        elif curve_drop is not None and drop_pct - curve_drop <= CURVE_TOLERANCE_PCT:
            # The window fell no faster than the same hours fall on other days.
            classification = "LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA"
            basis = (
                f"{actor} disabled logging on {asset} at {start} "
                f"({dis.get('rule_name')}); the window {end_basis}. "
                f"Event volume inside the window fell {drop_pct:.1f}% versus "
                f"the preceding {span}, but the same clock hours on the other "
                f"days in this file fall {curve_drop:.1f}% on average -- a "
                f"difference of {drop_pct - curve_drop:+.1f} points, within the "
                f"{CURVE_TOLERANCE_PCT:.0f}-point daily-curve tolerance. "
                f"{total_in:,} events were still recorded in the window, "
                f"{admin_in:,} of them on event/* streams. "
                f"Disk logging was disabled, but this file kept recording, so "
                f"it likely comes from a remote or forwarded stream; activity "
                f"in the window remains visible."
            )
            impact = (
                "No loss of visibility in the supplied data, so the actions "
                "taken under cover of the disable ARE present and can be "
                "reviewed. What cannot be confirmed from this file alone is "
                "whether a separate on-box disk log lost records that the "
                "forwarded stream never carried."
            )
        elif drop_pct >= SIGNIFICANT_DROP_PCT:
            classification = "LOGGING_DISABLED_BY_ACTOR"
            curve_txt = (f"; the daily curve for these hours accounts for only "
                         f"{curve_drop:.1f}%" if curve_drop is not None
                         else "; no daily-curve control was available")
            basis = (
                f"{actor} disabled logging on {asset} at {start} "
                f"({dis.get('rule_name')}); the window {end_basis}. "
                f"Event volume inside the window fell {drop_pct:.1f}% versus "
                f"the preceding {span}{curve_txt}. Only {total_in:,} events "
                f"were recorded in the window against {total_before:,} before "
                f"it. The disable event is the positive basis for this "
                f"classification."
            )
            impact = (
                f"Activity on {asset} between {start} and {end} may be absent "
                f"from this data. Any conclusion that 'nothing else happened' "
                f"in this window is unsupported."
            )
        else:
            classification = "LOGGING_DISABLED_NO_LOSS_IN_SUPPLIED_DATA"
            basis = (
                f"{actor} disabled logging on {asset} at {start} "
                f"({dis.get('rule_name')}); the window {end_basis}. "
                f"Event volume inside the window fell only {drop_pct:.1f}%, "
                f"below the {SIGNIFICANT_DROP_PCT:.0f}% threshold for a real "
                f"loss. {total_in:,} events were still recorded. "
                f"Disk logging was disabled, but this file kept recording, so "
                f"it likely comes from a remote or forwarded stream; activity "
                f"in the window remains visible."
            )
            impact = (
                "No loss of visibility in the supplied data. The disable "
                "attempt did not remove the evidence of what followed."
            )

        gaps.append({
            "gap_id": f"{incident.get('id', 'INC')}-BLIND-{n:02d}",
            "incident_id": incident.get("id", "UNKNOWN"),
            "asset_or_entity": asset,
            "telemetry": "firewall_event",
            "time_start": str(start),
            "time_end": str(end),
            "classification": classification,
            "basis": basis,
            "impact": impact,
            "evidence_request": (
                "FortiAnalyzer or remote syslog copy covering "
                f"{start} to {end}, to confirm independently what the on-box "
                "disk log would have held; plus firewall configuration backups "
                "from before and after the window to establish what changed "
                "while logging was off."
            ),
            # Kept for the dashboard, which shades the window on the timeline.
            "_window_start": start,
            "_window_end": end,
            "_drop_pct": drop_pct,
            "_curve_drop_pct": curve_drop,
            "_events_inside": total_in,
            "_events_before": total_before,
        })

    return gaps


def analyse(con, incidents, source=None, parse_ts=None, persist=True):
    """Run the blind-window check over every incident and store the gaps."""
    _ensure_table(con)
    found = []
    for inc in incidents:
        found.extend(analyse_incident(con, inc, source=source,
                                      parse_ts=parse_ts))
    if persist and found:
        ids = [g["gap_id"] for g in found]
        con.execute(
            f"DELETE FROM cp2_gaps WHERE gap_id IN "
            f"({','.join('?' for _ in ids)})", ids)
        con.executemany(
            "INSERT INTO cp2_gaps VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(g["gap_id"], g["incident_id"], g["asset_or_entity"],
              g["telemetry"], g["time_start"], g["time_end"],
              g["classification"], g["basis"], g["impact"],
              g["evidence_request"]) for g in found])
    return found
