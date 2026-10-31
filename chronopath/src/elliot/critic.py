"""
Adversarial self-review: the investigator argues with its own conclusion.

Before a theory is presented, each of these questions is answered from the
evidence pack. A question that exposes a weakness is marked "concern", and the
confidence attached to the theory is lowered accordingly. Confidence can never
be "high" while sources the conclusion depends on were not supplied: missing
telemetry caps certainty, it does not get interpreted away.
"""

QUESTIONS = (
    "Am I assuming causation from correlation?",
    "Am I overlooking a legitimate explanation?",
    "Is this conclusion supported by direct evidence?",
    "Does contradictory evidence exist?",
    "Am I interpreting missing telemetry correctly?",
    "What would disprove my hypothesis?",
    "Am I overlooking another possible attack sequence?",
)


def review(h, pack, hypotheses):
    """Answer every question for one theory. Returns (answers, confidence, why)."""
    by_id = {x.id: x for x in hypotheses}
    cited = {c for x in h.supports for c in x["cites"]}
    links = [pack.get(c) for c in cited if c.startswith("L")]
    soft = [l for l in pack.of("L") if l.data.get("grade") != "HARD"]
    direct = [x for x in h.supports if any(c.startswith("E") for c in x["cites"])]
    gaps = [g for g in pack.of("G") if "NOT_COLLECTED" in g.data["classification"]
            or "UNKNOWN" in g.data["classification"]]
    answers = []

    # 1. Correlation vs causation
    if soft:
        answers.append(("concern", f"Partly. {len(soft)} link(s) in this incident are "
                        f"SOFT or INFERRED -- they show proximity, not cause.",
                        [l.id for l in soft]))
    elif links or pack.of("L"):
        answers.append(("ok", "The links relied on are HARD (same account, or one "
                        "record naming both identities).", [l.id for l in pack.of("L")]))
    else:
        answers.append(("concern", "There are no recorded links: the sequence is "
                        "ordered by time alone.", []))

    # 2. Legitimate explanation
    benign = by_id.get("H3")
    if h.id == "H3":
        answers.append(("ok", "This is the legitimate explanation.", []))
    elif benign and benign.status != "abandoned":
        answers.append(("concern", f"Possibly. The routine-administration theory is still "
                        f"{benign.status}: {benign.status_reason}",
                        [c for x in benign.supports for c in x["cites"]]))
    elif benign:
        answers.append(("ok", f"Considered and abandoned: {benign.status_reason}",
                        [c for x in benign.challenges for c in x["cites"]]))

    # 3. Direct evidence
    if direct:
        answers.append(("ok", f"Yes: {len(direct)} supporting point(s) cite detections "
                        f"directly.", sorted({c for x in direct for c in x["cites"]
                                              if c.startswith("E")})))
    else:
        answers.append(("concern", "No. Its support is indirect (wider data, links or "
                        "absence), not a detection that shows it.", sorted(cited)))

    # 4. Contradictions
    if h.challenges:
        answers.append(("concern", "Yes: " + "; ".join(x["text"] for x in h.challenges),
                        sorted({c for x in h.challenges for c in x["cites"]})))
    else:
        answers.append(("ok", "None found in the supplied data.", []))

    # 5. Missing telemetry
    if gaps:
        answers.append(("concern", f"{len(gaps)} source(s) were never supplied. Their "
                        f"absence is treated as unknown -- not as proof that nothing "
                        f"happened, and not as proof that something did.",
                        [g.id for g in gaps]))
    else:
        answers.append(("ok", "No gap was recorded for this incident.", []))

    # 6. Disproof
    answers.append(("ok", h.disproof or "Not stated.", []))

    # 7. Other sequences
    others = [x for x in hypotheses if x.id != h.id and x.status in ("leading", "plausible")]
    if others:
        answers.append(("concern", "Other explanations remain open: "
                        + "; ".join(f"{x.id} {x.title} ({x.status})" for x in others), []))
    else:
        answers.append(("ok", "No competing explanation is currently plausible.", []))

    concerns = sum(1 for a in answers if a[0] == "concern")
    if h.status in ("abandoned", "unsupported"):
        confidence, why = "none", h.status_reason
    elif not direct or h.score <= 0:
        confidence, why = "low", "Indirect support only, or as much against as for."
    elif concerns <= 2 and not gaps:
        confidence, why = "high", "Direct evidence, HARD links, few open concerns."
    else:
        confidence = "moderate"
        why = ("Capped by sources that were not supplied." if gaps
               else f"{concerns} open concern(s) in the self-review.")
    return ([{"question": q, "verdict": v, "answer": a, "cites": c}
             for q, (v, a, c) in zip(QUESTIONS, answers)], confidence, why)
