"""Conversations of the mock computer (docs/ios/protocol-draft.md, protocol v1).

A chat is a conversation with the simulated agent. Each request the person sends starts a replay of the demo mission;
the mission's progress is turned into chat items: the agent's messages, its activities (search, read, compare…),
the confirmations it waits for, and the exposure report at the end. Everything is labelled "mode": "mock" by the
server.
"""

from __future__ import annotations

import secrets
import time
from typing import Callable

MAX_TEXT = 2000

# What the agent is doing while a step runs (shown with a spinner on the phone).
RUNNING_LABELS = {
    "search": "Recherche en cours…",
    "read": "Lecture d'une page…",
    "compare": "Comparaison des offres…",
    "contact": "Prise de contact…",
    "prepare_payment": "Préparation du paiement…",
    "pay": "Envoi du paiement…",
}

PLAN_MESSAGE = ("J'ai préparé un plan en 9 étapes. Il est figé avant toute lecture du web : je ne contacterai personne "
                "et ne paierai rien sans votre accord. Validez-le pour que je commence.")
RECIPIENT_MESSAGE = "J'ai trouvé deux offres. Laquelle dois-je contacter ?"
PAYMENT_MESSAGE = "Le cabinet est contacté. Il reste à confirmer le paiement de la consultation."
DONE_MESSAGE = ("C'est fait : cabinet contacté et consultation payée. Voici ce qui est sorti de votre ordinateur "
                "pendant cette mission.")
CANCELLED_MESSAGE = "Mission arrêtée à votre demande. Rien d'autre ne sera envoyé."
BUSY_MESSAGE = ("Je suis encore sur la mission en cours : je vous tiens au courant ici. "
                "(Simulation : l'agent de démonstration ne répond pas encore aux messages pendant une mission.)")


def title_from(text: str) -> str:
    line = " ".join(text.split())
    return line if len(line) <= 48 else line[:47].rstrip() + "…"


class Chat:
    def __init__(self, text: str, make_mission: Callable[[], object]):
        self.id = "chat-" + secrets.token_hex(16)  # random, never reused
        self.title = title_from(text)
        self.created_at = self.updated_at = int(time.time())
        self.items: list[dict] = []
        self._item_count = 0
        self._make_mission = make_mission
        self.mission = None
        self._seen_events = 0
        self.decisions: dict[str, str] = {}  # confirmation id -> "accepted" / "rejected"
        self.message(text)

    # -- items -----------------------------------------------------------------------------------
    def _add(self, kind: str, **data) -> None:
        self._item_count += 1
        self.updated_at = int(time.time())
        self.items.append({"id": f"{self.id}-i-{self._item_count}", "kind": kind, "at": self.updated_at, **data})

    def _add_confirmation(self) -> None:
        if self.mission is not None and self.mission.pending is not None:
            self._add("confirmation", pending=self.mission.pending)

    @property
    def active(self) -> bool:
        return self.mission is not None and self.mission.phase not in ("closed", "cancelled")

    # -- the person's messages -------------------------------------------------------------------
    def message(self, text: str) -> None:
        self._add("user", text=text)
        if self.active:
            self._add("agent", text=BUSY_MESSAGE)
            return
        self.mission = self._make_mission()
        self._seen_events = len(self.mission.events)
        self._add("activity", tool="think", text="Lecture de votre demande et préparation d'un plan")
        self._add("agent", text=PLAN_MESSAGE)
        self._add_confirmation()

    def confirm(self, body: dict) -> str | None:
        pending = self.mission.pending if self.mission else None
        error = self.mission.confirm(body) if self.mission else "no mission"
        if error is None and pending is not None:
            self.decisions[pending["id"]] = "accepted" if body.get("decision") == "accept" else "rejected"
            self.updated_at = int(time.time())
            self._sync()
        return error

    def waits_for(self, confirmation_id: str) -> bool:
        return bool(self.mission and self.mission.pending and self.mission.pending["id"] == confirmation_id)

    # -- the agent's progress --------------------------------------------------------------------
    def tick(self) -> None:
        if self.active:
            self.mission.tick()
            self._sync()

    def _sync(self) -> None:
        """Turns new mission events into chat items."""
        events = self.mission.events[self._seen_events:]
        self._seen_events = len(self.mission.events)
        for event in events:
            if event.get("tool"):
                self._add("activity", tool=event["tool"], text=event["text"])
        if self.mission.phase == "waiting" and self.mission.pending is not None:
            if not any(i["kind"] == "confirmation" and i["pending"]["id"] == self.mission.pending["id"]
                       for i in self.items):
                kind = self.mission.pending["kind"]
                self._add("agent", text=RECIPIENT_MESSAGE if kind == "recipient" else PAYMENT_MESSAGE)
                self._add_confirmation()
        if self.mission.phase in ("closed", "cancelled") and not any(i["kind"] == "exposure" for i in self.items):
            self._add("agent", text=DONE_MESSAGE if self.mission.phase == "closed" else CANCELLED_MESSAGE)
            self._add("exposure", exposure=self.mission.exposure())

    # -- views -----------------------------------------------------------------------------------
    @property
    def status(self) -> str:
        if self.mission is None:
            return "idle"
        if self.mission.phase in ("plan_proposed", "waiting"):
            return "waiting"
        if self.mission.phase == "running":
            return "working"
        return "idle"

    def working(self) -> dict | None:
        """The step in progress, for the phone's spinner line."""
        if self.mission is None or self.mission.phase != "running":
            return None
        plan = self.mission.plan_steps()
        tool = plan[self.mission.cursor] if self.mission.cursor < len(plan) else None
        if tool not in RUNNING_LABELS:
            return None
        return {"tool": tool, "text": RUNNING_LABELS[tool]}

    def summary(self) -> dict:
        texts = [i["text"] for i in self.items if i["kind"] in ("user", "agent")]
        return {"id": self.id, "title": self.title, "updated_at": self.updated_at,
                "preview": texts[-1] if texts else "", "status": self.status}

    def view(self) -> dict:
        items = []
        for item in self.items:
            if item["kind"] == "confirmation":
                cid = item["pending"]["id"]
                state = "pending" if self.waits_for(cid) else self.decisions.get(cid, "expired")
                item = dict(item, state=state)
            items.append(item)
        return {"id": self.id, "title": self.title, "status": self.status, "working": self.working(),
                "items": items}
