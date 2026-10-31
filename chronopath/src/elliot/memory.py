"""
Investigation memory: what has been looked at, decided, done and rejected.

One JSON file per incident, under investigations/<database>/. The file is keyed
by the incident's CONTENT (a hash of its detections), not its ID: re-running
detection renumbers incidents, and INC-02 tomorrow may be a different attack.

Recommendations are remembered with a fingerprint of the evidence they cited.
A completed or dismissed one is not suggested again -- unless that evidence
has since changed, in which case it comes back marked "revisit".
"""

import hashlib
import json
import os
import tempfile
from datetime import datetime

ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "investigations")


def incident_key(incident):
    parts = sorted(f"{e['timestamp']}|{e['rule_name']}|{e['host']}|{e['user']}"
                   for e in incident["events"])
    return hashlib.sha1("\n".join(parts).encode("utf-8")).hexdigest()[:16]


def evidence_fingerprint(pack, cites):
    text = "\n".join(f"{c}:{pack.get(c).text}" for c in sorted(set(cites)) if pack.get(c))
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]


def _now():
    return datetime.now().isoformat(timespec="seconds")


class Memory:
    def __init__(self, db_path, incident, root=None):
        db = os.path.splitext(os.path.basename(db_path))[0]
        self.dir = os.path.join(root or ROOT, db)
        self.path = os.path.join(self.dir, f"{incident_key(incident)}.json")
        self.data = {
            "incident_id": incident["id"], "created": _now(), "updated": _now(),
            "examined": [],        # evidence IDs the analyst has looked at
            "findings_seen": [],   # finding keys already presented
            "hypotheses": {},      # id -> {last_status, verdict, reason, history}
            "recommendations": {}, # key -> {text, status, fingerprint, ...}
            "decisions": [],       # {at, text}
            "actions": [],         # {at, text}
            "unresolved": [],      # open questions
            "conversation": [],    # {at, role, text, intent}
        }
        if os.path.exists(self.path):
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.data.update(json.load(f))
            except (OSError, ValueError):
                pass   # an unreadable memory file starts a fresh investigation
        self.data["incident_id"] = incident["id"]

    def save(self):
        self.data["updated"] = _now()
        os.makedirs(self.dir, exist_ok=True)
        # Write-then-rename so a crash never leaves a half-written file.
        fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=1, default=str)
        os.replace(tmp, self.path)

    # -- evidence and findings ----------------------------------------------
    def mark_examined(self, ids):
        for i in ids:
            if i not in self.data["examined"]:
                self.data["examined"].append(i)

    def mark_seen(self, keys):
        for k in keys:
            if k not in self.data["findings_seen"]:
                self.data["findings_seen"].append(k)

    # -- hypotheses ----------------------------------------------------------
    def track_hypotheses(self, hypotheses):
        """Record status changes; returns the theories abandoned since last time."""
        newly_abandoned = []
        for h in hypotheses:
            rec = self.data["hypotheses"].setdefault(
                h.id, {"title": h.title, "last_status": None, "verdict": None,
                       "reason": "", "history": []})
            if rec["last_status"] != h.status:
                if rec["last_status"] not in (None, "abandoned") and h.status == "abandoned":
                    newly_abandoned.append(h)
                rec["history"].append({"at": _now(), "status": h.status,
                                       "why": h.status_reason})
                rec["last_status"] = h.status
        return newly_abandoned

    def set_verdict(self, hid, verdict, reason=""):
        rec = self.data["hypotheses"].setdefault(
            hid, {"title": hid, "last_status": None, "verdict": None,
                  "reason": "", "history": []})
        rec["verdict"], rec["reason"] = verdict, reason
        rec["history"].append({"at": _now(), "status": f"analyst: {verdict}",
                               "why": reason})
        if verdict == "rejected":
            self.add_decision(f"Rejected {hid} ({rec['title']}): {reason or 'no reason given'}")
        elif verdict == "accepted":
            self.add_decision(f"Accepted {hid} ({rec['title']}) as working theory")

    def verdict(self, hid):
        return (self.data["hypotheses"].get(hid) or {}).get("verdict")

    def rejected(self):
        return {hid: r for hid, r in self.data["hypotheses"].items()
                if r.get("verdict") == "rejected"}

    # -- recommendations -----------------------------------------------------
    def offer(self, key, text, fingerprint):
        """
        Register a recommendation. Returns its state for display:
        'new', 'open', 'revisit' (done/dismissed but its evidence changed),
        or None when it was completed and nothing has changed.
        """
        recs = self.data["recommendations"]
        rec = recs.get(key)
        if rec is None:
            recs[key] = {"text": text, "status": "open", "fingerprint": fingerprint,
                         "first_suggested": _now(), "last_suggested": _now()}
            return "new"
        rec["last_suggested"] = _now()
        if rec["status"] in ("done", "dismissed"):
            if rec.get("fingerprint") != fingerprint:
                rec["status"], rec["fingerprint"] = "open", fingerprint
                rec["text"] = text
                return "revisit"
            return None
        rec["text"], rec["fingerprint"] = text, fingerprint
        return "open"

    def resolve(self, key, status, note=""):
        rec = self.data["recommendations"].get(key)
        if rec is None:
            return False
        rec["status"], rec["resolved_at"], rec["note"] = status, _now(), note
        verb = "Completed" if status == "done" else "Dismissed"
        self.data["actions"].append({"at": _now(), "text": f"{verb}: {rec['text']}"
                                     + (f" -- {note}" if note else "")})
        return True

    # -- decisions, questions, conversation ----------------------------------
    def add_decision(self, text):
        self.data["decisions"].append({"at": _now(), "text": text})

    def add_question(self, text):
        if text not in self.data["unresolved"]:
            self.data["unresolved"].append(text)

    def close_question(self, text):
        if text in self.data["unresolved"]:
            self.data["unresolved"].remove(text)

    def say(self, role, text, intent=""):
        self.data["conversation"].append({"at": _now(), "role": role,
                                          "text": text, "intent": intent})
        self.data["conversation"] = self.data["conversation"][-200:]

    def summary(self):
        recs = self.data["recommendations"].values()
        return {
            "examined": len(self.data["examined"]),
            "decisions": len(self.data["decisions"]),
            "done": sum(1 for r in recs if r["status"] == "done"),
            "dismissed": sum(1 for r in recs if r["status"] == "dismissed"),
            "open": sum(1 for r in recs if r["status"] == "open"),
            "rejected_theories": len(self.rejected()),
            "unresolved": len(self.data["unresolved"]),
        }
