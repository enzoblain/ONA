#!/usr/bin/env python3
"""Fake ONA computer for the iOS app (steps 2 and 3). Everything it returns is labelled "mode": "mock".

Follows docs/ios/protocol-draft.md (draft v0) and replays the demo mission of ona-core
(crates/ona-core on main): same plan, same two offers, same payment bytes and digest.

Step 3: the phone pairs with a QR code (printed in the terminal as text; `--qr` also opens it as an image) and every
confirmation must be signed by the paired phone's key.

Standard library only. Usage:
    python3 mock_computer.py [--port 8790] [--host 127.0.0.1] [--step-seconds 3] [--qr]
Use --host 0.0.0.0 to reach it from an iPhone on the same network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pairing import Pairing

MODE = "mock"

# Same values as ona-core's demo (DEMO_PLAN, MockWeb::demo, demo_policy).
DEMO_TITLE = "Trouver un avocat en droit du travail"
DEMO_PLAN = ["search", "read", "read", "compare", "confirm_recipient", "contact",
             "prepare_payment", "confirm_payment", "pay"]
DEMO_OFFERS = [
    {"firm_id": "cabinet-a", "specialties": ["labour"], "price_cents": 90_000, "delay_days": 7,
     "source_spans": ["Consultation 900 euros, sous 7 jours"]},
    {"firm_id": "cabinet-b", "specialties": ["labour"], "price_cents": 60_000, "delay_days": 10,
     "source_spans": ["Forfait 600 euros, sous 10 jours"]},
]
DIRECTORY = {"cabinet-a": "cabinet-a.testnet", "cabinet-b": "cabinet-b.testnet"}
DEMO_AMOUNT = 1_000_000_000_000_000_000_000_000  # 1 NEAR in yoctoNEAR, as in ona-core's `ona demo`

CONFIRM_STEPS = {"confirm_recipient": "recipient", "confirm_payment": "payment"}


def payment_bytes(to: str, amount: int) -> bytes:
    """Same bytes as ona-core gate::PaymentIntent::bytes: u32 LE length, UTF-8 account, u128 LE amount."""
    account = to.encode("utf-8")
    return struct.pack("<I", len(account)) + account + amount.to_bytes(16, "little")


def payment_digest(to: str, amount: int) -> str:
    return hashlib.sha256(payment_bytes(to, amount)).hexdigest()


def payment_screen(to: str, amount: int) -> str:
    return f"Pay {amount} yoctoNEAR to {to}"


class Mission:
    """A replay of the demo mission. The computer advances on its own and stops at each human confirmation."""

    def __init__(self, number: int):
        self.id = f"m-{number}"
        self.phase = "plan_proposed"
        self.cursor = 0  # index in DEMO_PLAN of the current step
        self.events: list[dict] = []
        self.chosen: str | None = None
        self.outputs: dict[str, int] = {}
        self.payments: list[dict] = []
        self.model_calls = 1  # the plan
        self.confirm_count = 0
        self.pending = self._new_pending("plan", plan=list(DEMO_PLAN))
        self.log("Mission ouverte, plan proposé")

    # -- helpers ---------------------------------------------------------------------------------
    def log(self, text: str) -> None:
        self.events.append({"at": int(time.time()), "text": text})

    def _new_pending(self, kind: str, **data) -> dict:
        self.confirm_count += 1
        return {"id": f"c-{self.confirm_count}", "kind": kind, **data}

    def _count(self, tool: str) -> None:
        self.outputs[tool] = self.outputs.get(tool, 0) + 1

    def payment(self) -> dict:
        to = DIRECTORY[self.chosen]
        return {"to": to, "amount": str(DEMO_AMOUNT), "screen": payment_screen(to, DEMO_AMOUNT),
                "digest": payment_digest(to, DEMO_AMOUNT)}

    # -- progress --------------------------------------------------------------------------------
    def tick(self) -> None:
        """Runs the current automatic step, or opens the confirmation it needs."""
        if self.phase != "running":
            return
        step = DEMO_PLAN[self.cursor]
        if step in CONFIRM_STEPS:
            kind = CONFIRM_STEPS[step]
            if kind == "recipient":
                self.pending = self._new_pending("recipient", offers=DEMO_OFFERS)
                self.log("En attente : choix du cabinet")
            else:
                self.pending = self._new_pending("payment", payment=self.payment())
                self.log("En attente : confirmation du paiement")
            self.phase = "waiting"
            return
        if step == "search":
            self._count("search")
            self.log("Recherche « avocat droit du travail paris » : 2 résultats")
        elif step == "read":
            n = DEMO_PLAN[: self.cursor + 1].count("read")
            self.model_calls += 1
            self._count("fetch")
            self.log(f"Lecture de la page {n} sur 2 (offre extraite)")
        elif step == "compare":
            self.log("Comparaison : 2 offres classées")
        elif step == "contact":
            self._count("contact")
            self.log(f"Message générique envoyé à {self.chosen}")
        elif step == "prepare_payment":
            self.log("Paiement préparé à partir de l'annuaire")
        elif step == "pay":
            p = self.payment()  # ona-core lists payments apart, not in "outputs"
            self.payments.append({"to": p["to"], "amount": p["amount"]})
            self.log(f"Paiement envoyé : mock-tx-{p['digest'][:16]}")
        self.cursor += 1
        if self.cursor == len(DEMO_PLAN):
            self.phase = "closed"
            self.log("Mission terminée, relevé d'exposition prêt")

    def confirm(self, body: dict) -> str | None:
        """Applies a confirmation. Returns an error message or None."""
        pending = self.pending
        if pending is None or body.get("id") != pending["id"]:
            return "stale confirmation"
        decision = body.get("decision")
        if decision not in ("accept", "reject"):
            return "decision must be accept or reject"
        if decision == "reject":
            self.pending = None
            self.phase = "cancelled"
            self.log(f"Refusé sur le téléphone ({pending['kind']}) : mission arrêtée")
            return None
        if pending["kind"] == "recipient":
            firm = body.get("firm")
            if firm not in DIRECTORY:
                return "unknown firm"
            self.chosen = firm
            self.log(f"Cabinet choisi sur le téléphone : {firm}")
        elif pending["kind"] == "payment":
            if body.get("digest") != pending["payment"]["digest"]:
                return "digest does not match the payment screen"
            self.log("Paiement confirmé sur le téléphone")
        else:
            self.log("Plan accepté sur le téléphone")
        self.pending = None
        self.phase = "running"
        if pending["kind"] != "plan":
            self.cursor += 1  # the confirmation step itself is done
        return None

    # -- view ------------------------------------------------------------------------------------
    def steps(self) -> list[dict]:
        out = []
        for i, step in enumerate(DEMO_PLAN):
            if self.phase == "closed" or i < self.cursor:
                status = "done"
            elif i == self.cursor and self.phase in ("running", "waiting"):
                status = "current"
            else:
                status = "pending"
            out.append({"step": step, "status": status})
        return out

    def view(self) -> dict:
        exposure = None
        if self.phase in ("closed", "cancelled"):
            exposure = {
                "outputs": self.outputs,
                "refused_by_gate": {},
                "firms_contacted": [self.chosen] if self.outputs.get("contact") else [],
                "payments": self.payments,
                "model_calls": self.model_calls,
                "mode": MODE,
            }
        return {"id": self.id, "title": DEMO_TITLE, "phase": self.phase, "steps": self.steps(),
                "events": self.events[-50:], "pending": self.pending, "exposure": exposure}


class Computer:
    def __init__(self, step_seconds: float, pairing: Pairing):
        self.pairing = pairing
        self.lock = threading.Lock()
        self.mission: Mission | None = None
        self.missions_started = 0
        self.step_seconds = step_seconds
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            time.sleep(self.step_seconds)
            with self.lock:
                if self.mission:
                    self.mission.tick()

    def start(self) -> None:
        with self.lock:
            self.missions_started += 1
            self.mission = Mission(self.missions_started)

    def reset(self) -> None:
        with self.lock:
            self.mission = None

    def state(self) -> dict:
        with self.lock:
            return {"mode": MODE, "computer": {"name": "Ordinateur simulé"},
                    "mission": self.mission.view() if self.mission else None}

    def confirm(self, body: dict) -> str | None:
        signature_error = self.pairing.check_confirmation(body)
        if signature_error:
            print(f"   confirmation refused: {signature_error}", flush=True)
            return signature_error
        with self.lock:
            if not self.mission:
                return "no mission"
            return self.mission.confirm(body)


def make_handler(computer: Computer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ona-mock-computer/0"

        def _send(self, status: int, payload: dict) -> None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _error(self, status: int, message: str) -> None:
            self._send(status, {"ok": False, "error": message, "mode": MODE})

        def do_GET(self):  # noqa: N802 (http.server naming)
            if self.path == "/v0/state":
                self._send(200, computer.state())
            elif self.path == "/v0/mock/pairing":
                self._send(200, {"payload": computer.pairing.payload(), "mode": MODE})
            else:
                self._error(404, "not found")

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            if length > 16_384:
                return self._error(413, "body too large")
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._error(400, "body is not JSON")
            if not isinstance(body, dict):
                return self._error(400, "body must be an object")
            if self.path == "/v0/pair":
                error, pairing_id, code = computer.pairing.pair(body)
                if error:
                    print(f"   pairing refused: {error}", flush=True)
                    return self._error(403, error)
                print(f"==> Phone paired ({pairing_id}). Verification code: {code[:3]} {code[3:]}", flush=True)
                return self._send(200, {"ok": True, "pairing_id": pairing_id, "mode": MODE})
            if self.path == "/v0/confirm":
                error = computer.confirm(body)
                return self._error(409, error) if error else self._send(200, {"ok": True, "mode": MODE})
            if self.path == "/v0/mock/start":
                computer.start()
                return self._send(200, {"ok": True, "mode": MODE})
            if self.path == "/v0/mock/reset":
                computer.reset()
                return self._send(200, {"ok": True, "mode": MODE})
            if self.path == "/v0/mock/unpair":
                computer.pairing.new_code()
                print_pairing(computer.pairing, qr=False)
                return self._send(200, {"ok": True, "mode": MODE})
            self._error(404, "not found")

        def log_message(self, fmt, *args):  # one short line per request
            print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}", flush=True)

    return Handler


def public_host(host: str) -> str:
    """The address a phone can use: the host itself, or this Mac's LAN address when listening on all interfaces."""
    if host not in ("0.0.0.0", "::"):
        return host
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # no packet is sent: only picks the outgoing interface
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"


def print_pairing(pairing: Pairing, qr: bool) -> None:
    payload = pairing.payload()
    where = pairing.onion or pairing.address
    print(f"==> Pairing QR text (single use, {where}):\n{payload}", flush=True)
    if qr:
        script = Path(__file__).with_name("pairing_qr.swift")
        out = Path("/tmp") / "ona-mock-pairing.png"
        try:
            subprocess.run(["swift", str(script), payload, str(out)], check=True, timeout=120)
            subprocess.run(["open", str(out)], check=False)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"   could not show the QR image: {e}", file=sys.stderr, flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument("--step-seconds", type=float, default=3.0)
    parser.add_argument("--no-start", action="store_true", help="do not open a demo mission at launch")
    parser.add_argument("--address", help="address put in the pairing QR (default: guessed from --host)")
    parser.add_argument("--qr", action="store_true", help="also open the pairing QR as an image (macOS)")
    parser.add_argument("--onion", help="step 4: put this .onion address in the QR instead of a local address "
                                        "(see run_onion.sh)")
    args = parser.parse_args()

    if args.onion:
        address = None
        onion = args.onion.strip()
        if not onion.endswith(".onion"):
            parser.error("--onion must end with .onion")
    else:
        address = args.address or f"http://{public_host(args.host)}:{args.port}"
        onion = None
    pairing = Pairing("Ordinateur simulé", address, onion)
    computer = Computer(args.step_seconds, pairing)
    if not args.no_start:
        computer.start()
    server = ThreadingHTTPServer((args.host, args.port), make_handler(computer))
    print(f"ONA mock computer (mode: mock) on http://{args.host}:{args.port}/v0/state", flush=True)
    print_pairing(pairing, qr=args.qr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
