"""
The Investigator: a sceptical analyst that works one incident at a time.

  brief()        what caught its attention, its theories and self-review, and
                 the next moves -- without being asked
  ask(question)  answers an analyst's question from the evidence, in the
                 seven-part format
  mark_examined / resolve / decide / set_verdict
                 the analyst's actions, kept in the investigation memory

THE DETERMINISTIC CORE ALWAYS ANSWERS. Everything above works with no API key
and no network. When GROQ_API_KEY is set, a language model may write the
answer in prose -- from the same evidence pack and analysis -- but that answer
is validated before it is shown. Any citation, timestamp or IP address that is
not in the evidence pack, or any claim to have carried out an action, discards
it and the deterministic answer is shown instead, with the reasons.
"""

import os
import re

import graph_engine

from . import analysts, critic, evidence, hypotheses as hyp
from .analysts import SECTION_LABELS, SECTION_TITLES, SECTIONS, refs
from .memory import Memory, evidence_fingerprint

# The analyst's standard questions, and the intent each one maps to.
QUESTIONS = {
    "What am I missing in this investigation?": "missing",
    "Find something unusual that has not been investigated.": "unusual",
    "Challenge my current attack theory.": "challenge",
    "Think of another explanation for this incident.": "alternative",
    "What would an attacker likely have done next?": "attacker_next",
    "Which evidence should I investigate first?": "prioritize",
    "Find connections I may have overlooked.": "connections",
    "Try to disprove this attack hypothesis.": "disprove",
}

# Free-text routing: first match wins, so the more specific intents come first.
INTENT_WORDS = (
    ("disprove", ("disprove", "prove wrong", "refute", "falsif")),
    ("challenge", ("challenge", "wrong about", "poke holes", "devil", "sure about",
                   "question my", "my theory", "current theory")),
    ("alternative", ("another explanation", "alternative", "other explanation",
                     "else could", "benign", "innocent", "legitimate")),
    ("attacker_next", ("next", "attacker do", "would they", "would an attacker",
                       "predict", "go next", "after this")),
    ("prioritize", ("first", "priorit", "start with", "most important", "where should")),
    ("connections", ("connection", "related", "relationship", "link", "overlooked")),
    ("unusual", ("unusual", "odd", "strange", "weird", "anomal", "suspicious", "stand out")),
    ("missing", ("missing", "miss", "gap", "blind", "don't know", "cannot see", "unknown")),
)

# What the kill chain says can follow a stage. Used only to phrase predictions.
LATER_STAGES = sorted(graph_engine.STAGE_ORDER, key=graph_engine.STAGE_ORDER.get)

ACTION_CLAIM = re.compile(
    r"\b(?:I|we)\s+(?:have\s+|'ve\s+|already\s+)?(?:checked|queried|ran|run|verified|"
    r"confirmed|executed|looked up|pulled|retrieved|contacted|reset|blocked|"
    r"isolated|scanned|interviewed)\b", re.IGNORECASE)
CITE_RE = re.compile(r"\[([A-Z]\d+(?:\s*,\s*[A-Z]\d+)*)\]")


def _clip(text, limit):
    """Shorten at a word boundary, never mid-word."""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(",;:") + " …"


def route(question):
    q = (question or "").strip()
    if q in QUESTIONS:
        return QUESTIONS[q]
    low = q.lower()
    for intent, words in INTENT_WORDS:
        if any(w in low for w in words):
            return intent
    return "general"


class Investigator:
    def __init__(self, db_path, incident, memory_root=None, use_llm=None):
        self.db_path = db_path
        self.incident = incident
        self.pack = evidence.build(db_path, incident)
        self.findings = analysts.observe(self.pack)
        self.questions = analysts.strategic_questions(self.pack)
        self.memory = Memory(db_path, incident, root=memory_root)
        self.hypotheses = hyp.generate(self.pack, self.findings)
        self._apply_verdicts()
        self.newly_abandoned = self.memory.track_hypotheses(self.hypotheses)
        self.reviews = {h.id: critic.review(h, self.pack, self.hypotheses)
                        for h in self.hypotheses}
        self.use_llm = (bool(os.environ.get("GROQ_API_KEY"))
                        if use_llm is None else use_llm)
        self.memory.save()

    # ------------------------------------------------------------------
    # Theories and the analyst's verdicts
    # ------------------------------------------------------------------
    def _apply_verdicts(self):
        for h in self.hypotheses:
            rec = self.memory.data["hypotheses"].get(h.id) or {}
            if rec.get("verdict") == "rejected":
                h.status = "rejected"
                h.status_reason = f"Rejected by the analyst: {rec.get('reason') or 'no reason given'}"
            elif rec.get("verdict") == "accepted" and h.status != "abandoned":
                h.status_reason += " The analyst accepted it as the working theory."
        accepted = [h for h in self.hypotheses if self.memory.verdict(h.id) == "accepted"
                    and h.status not in ("abandoned", "rejected")]
        live = [h for h in self.hypotheses if h.status in ("leading", "plausible")]
        if accepted or not any(h.status == "leading" for h in live):
            for h in live:
                h.status = "plausible"
            lead = accepted[0] if accepted else (max(live, key=lambda h: h.score) if live else None)
            if lead:
                lead.status = "leading"
        order = {"leading": 0, "plausible": 1, "weakened": 2, "unsupported": 3,
                 "abandoned": 4, "rejected": 5}
        self.hypotheses.sort(key=lambda h: (order[h.status], -h.score))

    def theory(self, hid=None):
        """The theory being discussed: named, accepted, or the leading one."""
        if hid:
            for h in self.hypotheses:
                if h.id == hid:
                    return h
        for h in self.hypotheses:
            if self.memory.verdict(h.id) == "accepted" and h.status != "rejected":
                return h
        return next((h for h in self.hypotheses if h.status == "leading"),
                    self.hypotheses[0] if self.hypotheses else None)

    # ------------------------------------------------------------------
    # Next moves, filtered by what has been done already
    # ------------------------------------------------------------------
    def next_moves(self, limit=8):
        cands = []
        for f in self.findings:
            if f.next_move and f.priority > 0:
                cands.append((f.priority, f"move:{f.key}", f.next_move,
                              f"{f.title}: {_clip(f.observation, 180)}", f.cites))
        lead = self.theory()
        if lead and lead.status not in ("abandoned", "rejected"):
            # The rival is the named alternative while it is alive, otherwise the
            # strongest other theory still standing.
            alive = [h for h in self.hypotheses if h is not lead
                     and h.status in ("plausible", "weakened")]
            alt = next((h for h in alive if h.id == lead.alternative),
                       alive[0] if alive else None)
            if alt:
                cands.append((78, f"discriminate:{lead.id}-{alt.id}",
                              f"Tell {lead.id} from {alt.id}: {lead.discriminator}",
                              f"The leading theory ({lead.title}) and its closest rival "
                              f"({alt.title}) are both still open.",
                              [c for x in lead.supports + alt.supports for c in x["cites"]]))
        for q in self.questions:
            cands.append((45, q["key"], f"{q['question']} Needed: {q['evidence_needed']}",
                          q["why"], q["cites"]))
        moves, seen_text = [], set()
        for priority, key, text, why, cites in sorted(cands, key=lambda c: -c[0]):
            if text in seen_text:
                continue
            state = self.memory.offer(key, text, evidence_fingerprint(self.pack, cites))
            if state is None:
                continue   # done or dismissed, and its evidence has not changed
            seen_text.add(text)
            moves.append({"key": key, "priority": priority + (5 if state == "revisit" else 0),
                          "action": text, "reason": why, "state": state,
                          "cites": sorted(set(cites)), "label": "RECOMMENDATION"})
        self.memory.save()
        moves.sort(key=lambda m: -m["priority"])
        return moves[:limit]

    # ------------------------------------------------------------------
    # The proactive brief
    # ------------------------------------------------------------------
    def brief(self):
        examined = set(self.memory.data["examined"])
        findings = []
        for f in self.findings:
            d = f.as_dict()
            d["examined"] = bool(f.cites) and set(f.cites) <= examined
            findings.append(d)
        return {
            "incident": {"id": self.incident["id"],
                         "risk_score": self.incident["risk_score"],
                         "window": [self.incident["start_time"], self.incident["end_time"]],
                         "detections": self.incident["detection_count"]},
            "findings": findings,
            "hypotheses": [self._theory_dict(h) for h in self.hypotheses],
            "abandoned_since_last_review": [
                {"id": h.id, "title": h.title, "reason": h.status_reason}
                for h in self.newly_abandoned],
            "next_moves": self.next_moves(),
            "questions": self.questions,
            "memory": self.memory.summary(),
            "evidence": [{"id": i.id, "label": i.label, "text": i.text}
                         for i in self.pack.items.values()],
        }

    def _theory_dict(self, h):
        answers, confidence, why = self.reviews[h.id]
        d = h.as_dict()
        d.update(self_review=answers, confidence=confidence, confidence_reason=why,
                 analyst_verdict=self.memory.verdict(h.id))
        return d

    # ------------------------------------------------------------------
    # Questions
    # ------------------------------------------------------------------
    def ask(self, question):
        intent = route(question)
        handler = getattr(self, f"_q_{intent}")
        answer = handler(question)
        answer.update(question=question, intent=intent, narrative=None,
                      narrative_source="deterministic", validation=None)
        if self.use_llm:
            text, problems = self._llm(question, answer)
            if text and not problems:
                answer.update(narrative=text, narrative_source="groq",
                              validation={"passed": True, "problems": []})
            elif text:
                answer["validation"] = {"passed": False, "problems": problems}
        self.memory.say("analyst", question, intent)
        self.memory.say("investigator", answer["headline"], intent)
        self.memory.save()
        return answer

    # Each handler returns {"headline", "sections": [7-part dicts], "extra": [...]}.
    def _q_missing(self, q):
        gaps_first = [f for f in self.findings if f.category == "missing evidence"]
        rest = [f for f in self.findings if f not in gaps_first][:2]
        external = [x for x in self.questions if x["where"].startswith("Not in")]
        for x in external:
            self.memory.add_question(x["question"])
        return {"headline": f"{len(gaps_first)} gap finding(s), "
                            f"{len(external)} question(s) the supplied data cannot answer.",
                "sections": [f.as_dict() for f in gaps_first + rest],
                "extra": [{"kind": "question", **x} for x in self.questions]
                + [{"kind": "unresolved", "text": t}
                   for t in self.memory.data["unresolved"]]}

    def _q_unusual(self, q):
        examined = set(self.memory.data["examined"])
        seen = set(self.memory.data["findings_seen"])
        fresh = [f for f in self.findings if f.priority > 0
                 and f.key not in seen and not set(f.cites) <= examined]
        pick = (fresh or [f for f in self.findings if f.priority > 0])[:3]
        self.memory.mark_seen(f.key for f in pick)
        note = ("" if fresh else
                " Everything has been presented before; repeating the strongest.")
        return {"headline": f"{len(pick)} observation(s) not yet investigated.{note}",
                "sections": [f.as_dict() for f in pick], "extra": []}

    def _named_theory(self, q):
        m = re.search(r"\bH(\d)\b", q or "")
        return self.theory(f"H{m.group(1)}" if m else None)

    def _q_challenge(self, q):
        h = self._named_theory(q)
        if not h:
            return {"headline": "There is no theory to challenge.", "sections": [], "extra": []}
        return {"headline": f"Challenging {h.id}: {h.title} ({h.status}, confidence "
                            f"{self.reviews[h.id][1]}).",
                "sections": [self._theory_section(h, "challenge")],
                "extra": [{"kind": "self_review", "theory": h.id,
                           "answers": self.reviews[h.id][0]}]}

    def _q_disprove(self, q):
        h = self._named_theory(q)
        if not h:
            return {"headline": "There is no theory to disprove.", "sections": [], "extra": []}
        against = h.challenges
        verdict = ("It already stands abandoned." if h.status == "abandoned" else
                   "The data does not disprove it." if not against else
                   f"{len(against)} piece(s) of evidence cut against it, "
                   f"but none settles it.")
        return {"headline": f"Trying to disprove {h.id}: {h.title}. {verdict}",
                "sections": [self._theory_section(h, "disprove")],
                "extra": [{"kind": "self_review", "theory": h.id,
                           "answers": self.reviews[h.id][0]}]}

    def _q_alternative(self, q):
        lead = self.theory()
        others = [h for h in self.hypotheses if h is not lead
                  and h.status not in ("abandoned", "rejected")]
        dropped = [h for h in self.hypotheses if h.status in ("abandoned", "rejected")]
        return {"headline": f"{len(others)} other explanation(s) remain open; "
                            f"{len(dropped)} were set aside.",
                "sections": [self._theory_section(h, "alternative") for h in others[:3]],
                "extra": [{"kind": "set_aside", "id": h.id, "title": h.title,
                           "reason": h.status_reason} for h in dropped]}

    def _q_attacker_next(self, q):
        if not self.pack.events:
            return {"headline": "No detections to project from.", "sections": [], "extra": []}
        last_item, last = self.pack.events[-1]
        rank = graph_engine.STAGE_ORDER.get(last["kill_chain_stage"], 0)
        later = [s for s in LATER_STAGES if graph_engine.STAGE_ORDER[s] > rank][:4]
        preds = self.pack.of("P")
        themes = [x["question"] for x in self.questions]
        section = {
            "observation": (f"The last detected step is {last['rule_name']} "
                            f"({last['kill_chain_stage']}) at {last['timestamp']}"
                            f"{refs([last_item.id])}."),
            "reasoning": (f"In the ATT&CK kill chain the stages after "
                          f"{last['kill_chain_stage']} are {', '.join(later) or 'none'}. "
                          f"An actor who stopped being detected did not necessarily stop."),
            "connection": ("Systems reachable from what was touched: "
                           + "; ".join(p.text for p in preds[:4]) + refs([p.id for p in preds[:4]])
                           if preds else "No reachable system was derived for this incident."),
            "hypothesis": ("PREDICTION, not observed: the actor's likely next moves were "
                           + (", ".join(later[:3]).lower() if later else "unclear")
                           + (f", reaching {preds[0].data['target']}" if preds else "")
                           + ". Nothing in the data shows any of this happened."),
            "counterargument": ("The incident may have ended at the last detection: "
                                "the goal was met, the actor was interrupted, or it was "
                                "never an attack (see the open theories)."),
            "unknowns": ("Whether any activity followed, on systems or in sources not "
                         f"supplied{refs([g.id for g in self.pack.of('G')])}."),
            "next_move": ("Check the reachable systems above for logins or connections "
                          f"after {last['timestamp']}"
                          + (f"; the open questions are: {' / '.join(themes[:2])}" if themes else "")
                          + "."),
            "title": "Where the actor would go next", "key": "attacker-next",
            "priority": 60, "category": "prediction",
            "cites": [last_item.id] + [p.id for p in preds[:4]],
            "labels": dict(SECTION_LABELS, hypothesis="PREDICTION", connection="PREDICTION"),
        }
        return {"headline": "A projection, labelled as prediction: none of it is observed.",
                "sections": [section],
                "extra": [{"kind": "prediction", "id": p.id, "text": p.text} for p in preds]}

    def _q_prioritize(self, q):
        moves = self.next_moves(limit=5)
        top_keys = {m["key"].split("move:", 1)[-1] for m in moves}
        sections = [f.as_dict() for f in self.findings if f.key in top_keys][:3]
        return {"headline": (f"Start with: {moves[0]['action']}" if moves
                             else "Every recommendation has been completed or dismissed."),
                "sections": sections,
                "extra": [{"kind": "move", **m} for m in moves]}

    def _q_connections(self, q):
        pick = [f for f in self.findings if f.category == "overlooked connection"]
        return {"headline": f"{len(pick)} connection(s) the incident did not include.",
                "sections": [f.as_dict() for f in pick[:4]],
                "extra": [{"kind": "wider", "id": x.id, "text": x.text}
                          for x in self.pack.of("X")]
                + [{"kind": "separation", "id": s.id, "text": s.text}
                   for s in self.pack.of("S")]}

    def _q_general(self, q):
        # Match evidence IDs or entity values named in the question.
        tokens = set(re.findall(r"[A-Za-z0-9_.\-]+", q or ""))
        ids = {t for t in tokens if t in self.pack.items}
        values = {t for t in tokens if len(t) > 3 and any(
            t in i.text for i in self.pack.items.values())}
        pick = [f for f in self.findings
                if ids & set(f.cites) or any(v in f.observation for v in values)]
        if not pick:
            out = self._q_missing(q)
            out["headline"] = ("I could not match that to specific evidence, so here is "
                               "what this investigation is missing. " + out["headline"])
            return out
        return {"headline": f"{len(pick)} finding(s) involve "
                            f"{', '.join(sorted(ids | values)[:5])}.",
                "sections": [f.as_dict() for f in pick[:4]], "extra": []}

    def _theory_section(self, h, mode):
        answers, confidence, why = self.reviews[h.id]
        concerns = [a for a in answers if a["verdict"] == "concern"]
        sup = "; ".join(x["text"] + refs(x["cites"]) for x in h.supports) or "nothing yet"
        con = "; ".join(x["text"] + refs(x["cites"]) for x in h.challenges)
        alt = next((x for x in self.hypotheses if x.id == h.alternative), None)
        counter = con or "No evidence in the data contradicts it."
        if concerns:
            counter += " Self-review concerns: " + " ".join(
                f"{a['question']} {a['answer']}" for a in concerns[:3])
        next_move = (f"To disprove it: look for {h.disproof[0].lower() + h.disproof[1:]}"
                     if mode == "disprove" and h.disproof else h.discriminator)
        return {
            "observation": f"Evidence for {h.id}: {sup}.",
            "reasoning": (f"{h.id} is {h.status} ({h.status_reason}) with confidence "
                          f"{confidence}: {why}"),
            "connection": (f"Its closest rival is {alt.id}, {alt.title} ({alt.status})."
                           if alt else "No rival theory is defined."),
            "hypothesis": h.suspects,
            "counterargument": counter,
            "unknowns": "; ".join(m["text"] + refs(m["cites"]) for m in h.missing)
                        or "Nothing specific recorded.",
            "next_move": next_move,
            "title": f"{h.id}: {h.title}", "key": f"theory:{h.id}", "priority": 0,
            "category": "theory",
            "cites": sorted({c for x in h.supports + h.challenges for c in x["cites"]}),
            "labels": dict(SECTION_LABELS),
        }

    # ------------------------------------------------------------------
    # The analyst's actions
    # ------------------------------------------------------------------
    def mark_examined(self, ids):
        self.memory.mark_examined([i for i in ids if i in self.pack.items])
        self.memory.save()

    def resolve(self, key, status="done", note=""):
        ok = self.memory.resolve(key, status, note)
        self.memory.save()
        return ok

    def decide(self, text):
        self.memory.add_decision(text)
        self.memory.save()

    def set_verdict(self, hid, verdict, reason=""):
        self.memory.set_verdict(hid, verdict, reason)
        self.memory.save()

    # ------------------------------------------------------------------
    # Optional language model, held to the evidence
    # ------------------------------------------------------------------
    def _llm(self, question, answer):
        try:
            from groq import Groq
        except ImportError:
            return None, ["groq package not installed"]
        mem = self.memory.data
        analysis = "\n".join(
            f"- {s.get('title', '')}: " + " | ".join(
                f"{SECTION_TITLES[k]}: {s[k]}" for k in SECTIONS if s.get(k))
            for s in answer["sections"])
        theories = "\n".join(f"- {h.id} {h.title}: {h.status} ({h.status_reason})"
                             for h in self.hypotheses)
        memory_text = (
            "Decisions: " + "; ".join(d["text"] for d in mem["decisions"][-10:]) + "\n"
            "Rejected theories: " + "; ".join(f"{k}: {v.get('reason')}"
                                              for k, v in self.memory.rejected().items()) + "\n"
            "Completed actions: " + "; ".join(a["text"] for a in mem["actions"][-10:]))
        system = (
            "You are a sceptical, observant cybersecurity investigator. Rules you must "
            "follow: (1) Use ONLY the evidence listed; cite every evidence-based "
            "statement with its ID in square brackets, e.g. [E2] or [L1, G3]. (2) Never "
            "invent events, timestamps, accounts, addresses or relationships. (3) Mark "
            "each statement as FACT, INFERENCE, HYPOTHESIS or PREDICTION. (4) Never claim "
            "you checked, queried or did anything; you can only recommend. (5) State "
            "uncertainty plainly. Answer with these seven headings in order: "
            "Observation, Reasoning, Connection, Hypothesis, Counterargument, Unknowns, "
            "Next move.")
        user = (f"EVIDENCE PACK for {self.incident['id']}:\n{self.pack.render()}\n\n"
                f"THEORIES:\n{theories}\n\nDETERMINISTIC ANALYSIS:\n{analysis}\n\n"
                f"INVESTIGATION MEMORY:\n{memory_text}\n\nANALYST QUESTION: {question}")
        try:
            client = Groq(api_key=os.environ["GROQ_API_KEY"])
            for model in ("openai/gpt-oss-120b", "openai/gpt-oss-20b"):
                try:
                    resp = client.chat.completions.create(
                        model=model, temperature=0.2, max_tokens=2500,
                        messages=[{"role": "system", "content": system},
                                  {"role": "user", "content": user}])
                    text = (resp.choices[0].message.content or "").strip()
                    if text:
                        return text, validate(text, self.pack, self.hypotheses)
                except Exception:  # noqa: BLE001
                    continue
        except Exception as exc:  # noqa: BLE001
            return None, [f"model unavailable: {exc}"]
        return None, ["model returned nothing"]


def validate(text, pack, hypotheses=()):
    """Every problem that makes a model answer unsafe to show."""
    problems = []
    allowed = set(pack.items) | {h.id for h in hypotheses}
    for group in CITE_RE.findall(text):
        for cid in re.split(r"\s*,\s*", group):
            if cid not in allowed:
                problems.append(f"cites {cid}, which is not in the evidence pack")
    known_ts = pack.known_timestamps()
    for ts in evidence.TS_RE.findall(text):
        norm = ts.replace(" ", "T")
        if not any(k.startswith(norm) or norm.startswith(k) for k in known_ts):
            problems.append(f"mentions timestamp {ts}, which no evidence contains")
    known_ips = pack.known_ips()
    for ip in evidence.IP_RE.findall(text):
        if ip not in known_ips:
            problems.append(f"mentions address {ip}, which no evidence contains")
    m = ACTION_CLAIM.search(text)
    if m:
        problems.append(f"claims an action was performed: '{m.group(0)}'")
    headings = sum(1 for t in SECTION_TITLES.values() if t.lower() in text.lower())
    if headings < 5:
        problems.append("does not follow the seven-part format")
    return sorted(set(problems))
