"""
The Investigator tab of the Streamlit dashboard.

Kept out of app.py so the dashboard gains one call, not three hundred lines.
Every value that came from the data is HTML-escaped before display: account
names and log messages are attacker-controlled text.
"""

import html

import streamlit as st

from .analysts import SECTION_LABELS, SECTION_TITLES, SECTIONS
from .engine import QUESTIONS, Investigator

TAG_COLOURS = {
    "FACT": "#1f4e8c", "INFERENCE": "#6b5b00", "HYPOTHESIS": "#7a3e00",
    "PREDICTION": "#7b2d6b", "RECOMMENDATION": "#2f6b2f",
}
STATUS_MARK = {"leading": "●", "plausible": "○", "weakened": "◌",
               "unsupported": "·", "abandoned": "×", "rejected": "⊘"}


def _tag(label):
    colour = TAG_COLOURS.get(label, "#555")
    return (f"<span style='font-variant:small-caps;letter-spacing:.04em;"
            f"font-size:.78rem;color:{colour};border:1px solid {colour};"
            f"padding:0 .3rem;margin-left:.35rem'>{label.lower()}</span>")


def _esc(text):
    return html.escape(str(text or ""))


def render_section(s):
    """One finding or answer in the seven-part format."""
    labels = s.get("labels") or SECTION_LABELS
    parts = []
    for k in SECTIONS:
        if s.get(k):
            parts.append(f"<p style='margin:.2rem 0 .55rem'><b>{SECTION_TITLES[k]}</b>"
                         f"{_tag(labels.get(k, ''))}<br>{_esc(s[k])}</p>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def render(db_path, incident):
    inv = Investigator(db_path, incident)
    brief = inv.brief()
    key = f"elliot-{incident['id']}"

    st.subheader("Investigator")
    st.caption(
        "A sceptical second reader of this incident. It questions the current story, "
        "looks for what correlation left out, and proposes what to check next. Every "
        "statement cites the evidence it rests on (E = detection, L = link, G = gap, "
        "X = elsewhere in the data, P = prediction), and is labelled as a fact, "
        "inference, hypothesis, prediction or recommendation. It never carries out "
        "an action; it only recommends one.")

    for a in brief["abandoned_since_last_review"]:
        st.info(f"Theory abandoned since the last review: {a['id']} {a['title']}. "
                f"{a['reason']}")

    # -- Next moves ------------------------------------------------------------
    st.markdown("#### Next moves")
    moves = brief["next_moves"]
    if not moves:
        st.caption("Every recommendation has been completed or dismissed.")
    for m in moves:
        left, mid, right = st.columns([8, 1, 1])
        flag = {"new": " (new)", "revisit": " (revisit: its evidence changed)"}.get(m["state"], "")
        left.markdown(f"**{m['priority']}** &nbsp; {_esc(m['action'])}{flag}"
                      f"<br><span style='color:#666;font-size:.88rem'>Why: "
                      f"{_esc(m['reason'])} {_esc(', '.join(m['cites']))}</span>",
                      unsafe_allow_html=True)
        if mid.button("Done", key=f"{key}-done-{m['key']}"):
            inv.resolve(m["key"], "done")
            st.rerun()
        if right.button("Dismiss", key=f"{key}-dis-{m['key']}"):
            inv.resolve(m["key"], "dismissed")
            st.rerun()

    # -- Findings --------------------------------------------------------------
    st.markdown("#### What caught my attention")
    for f in brief["findings"]:
        if f["priority"] <= 0:
            continue
        mark = " — examined" if f["examined"] else ""
        with st.expander(f"{f['title']}  ·  {f['category']}  ·  priority {f['priority']}{mark}"):
            render_section(f)
            if not f["examined"] and f["cites"]:
                if st.button("Mark evidence examined", key=f"{key}-ex-{f['key']}"):
                    inv.mark_examined(f["cites"])
                    st.rerun()

    # -- Theories --------------------------------------------------------------
    st.markdown("#### Theories")
    st.caption("Status is computed from the evidence. Two strong contradictions abandon "
               "a theory; you can accept or reject one yourself, and the decision is kept.")
    for h in brief["hypotheses"]:
        verdict = f" — you {h['analyst_verdict']} it" if h["analyst_verdict"] else ""
        title = (f"{STATUS_MARK.get(h['status'], '')} {h['id']} {h['title']}  ·  "
                 f"{h['status']}  ·  confidence {h['confidence']}{verdict}")
        with st.expander(title):
            st.markdown(f"*{_esc(h['suspects'])}*  \n{_esc(h['status_reason'])} "
                        f"Confidence: **{h['confidence']}** — {_esc(h['confidence_reason'])}",
                        unsafe_allow_html=True)
            rows = ([("for", x) for x in h["supports"]] +
                    [("against", x) for x in h["challenges"]])
            if rows:
                st.table([{"": side, "Evidence": x["text"],
                           "Weight": x["strength"], "Cites": ", ".join(x["cites"])}
                          for side, x in rows])
            if h["missing"]:
                st.markdown("**Missing:** " + _esc("; ".join(
                    m["text"] + (f" [{', '.join(m['cites'])}]" if m["cites"] else "")
                    for m in h["missing"])), unsafe_allow_html=True)
            st.markdown(f"**To tell it apart:** {_esc(h['discriminator'])}  \n"
                        f"**Would be disproved by:** {_esc(h['disproof'])}",
                        unsafe_allow_html=True)
            st.markdown("**Self-review**")
            st.table([{"Question": r["question"], "": r["verdict"],
                       "Answer": r["answer"], "Cites": ", ".join(r["cites"])}
                      for r in h["self_review"]])
            reason = st.text_input("Reason (optional)", key=f"{key}-why-{h['id']}")
            c1, c2, _ = st.columns([1, 1, 4])
            if c1.button("Accept", key=f"{key}-acc-{h['id']}"):
                inv.set_verdict(h["id"], "accepted", reason)
                st.rerun()
            if c2.button("Reject", key=f"{key}-rej-{h['id']}"):
                inv.set_verdict(h["id"], "rejected", reason)
                st.rerun()

    # -- Conversation ----------------------------------------------------------
    st.markdown("#### Ask the investigator")
    cols = st.columns(2)
    asked = None
    for n, q in enumerate(QUESTIONS):
        if cols[n % 2].button(q, key=f"{key}-q-{n}", width="stretch"):
            asked = q
    with st.form(f"{key}-form", clear_on_submit=True):
        text = st.text_input("Your question",
                             placeholder="e.g. Is 7.39.133.59 involved anywhere else?")
        if st.form_submit_button("Ask") and text.strip():
            asked = text.strip()
    if asked:
        with st.spinner("Thinking it through..."):
            st.session_state[f"{key}-answer"] = inv.ask(asked)
    answer = st.session_state.get(f"{key}-answer")
    if answer:
        st.markdown(f"**Q:** {_esc(answer['question'])}  \n**A:** {_esc(answer['headline'])}",
                    unsafe_allow_html=True)
        if answer["narrative"]:
            st.markdown(answer["narrative"])
            st.caption("Written by the language model and validated: every citation, "
                       "timestamp and address it uses exists in the evidence.")
        else:
            if answer.get("validation") and not answer["validation"]["passed"]:
                st.warning("The language model's answer was discarded: "
                           + "; ".join(answer["validation"]["problems"]))
            for s in answer["sections"]:
                st.markdown(f"**{_esc(s.get('title', ''))}**", unsafe_allow_html=True)
                render_section(s)
        for x in answer["extra"]:
            kind = x.get("kind")
            if kind == "move":
                st.markdown(f"- **{x['priority']}** {_esc(x['action'])}", unsafe_allow_html=True)
            elif kind == "question":
                st.markdown(f"- {_esc(x['question'])} — {_esc(x['where'])}",
                            unsafe_allow_html=True)
            elif kind == "self_review":
                st.table([{"Question": r["question"], "": r["verdict"], "Answer": r["answer"]}
                          for r in x["answers"]])
            elif "text" in x:
                st.markdown(f"- {_esc(x.get('id', ''))} {_esc(x['text'])}",
                            unsafe_allow_html=True)
            elif "reason" in x:
                st.markdown(f"- {_esc(x['id'])} {_esc(x['title'])}: {_esc(x['reason'])}",
                            unsafe_allow_html=True)

    # -- Memory ----------------------------------------------------------------
    mem = inv.memory.data
    with st.expander(f"Investigation memory  ·  {brief['memory']['decisions']} decision(s), "
                     f"{brief['memory']['done']} done, {brief['memory']['unresolved']} open question(s)"):
        with st.form(f"{key}-decide", clear_on_submit=True):
            note = st.text_input("Record a decision")
            if st.form_submit_button("Record") and note.strip():
                inv.decide(note.strip())
                st.rerun()
        for title, rows, field in (("Decisions", mem["decisions"], "text"),
                                   ("Actions", mem["actions"], "text")):
            if rows:
                st.markdown(f"**{title}**")
                for r in rows[-15:]:
                    st.markdown(f"- {_esc(r['at'])} — {_esc(r[field])}", unsafe_allow_html=True)
        if mem["unresolved"]:
            st.markdown("**Unresolved questions**")
            for q in mem["unresolved"]:
                st.markdown(f"- {_esc(q)}", unsafe_allow_html=True)
        rejected = inv.memory.rejected()
        if rejected:
            st.markdown("**Rejected explanations**")
            for hid, r in rejected.items():
                st.markdown(f"- {_esc(hid)} {_esc(r.get('title'))}: {_esc(r.get('reason'))}",
                            unsafe_allow_html=True)
        st.caption(f"Stored in {inv.memory.path}")

    with st.expander(f"Evidence pack  ·  {len(brief['evidence'])} item(s)"):
        st.table([{"ID": e["id"], "": e["label"], "Evidence": e["text"]}
                  for e in brief["evidence"]])
