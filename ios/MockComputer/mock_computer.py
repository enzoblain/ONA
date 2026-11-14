#!/usr/bin/env python3
"""Fake ONA computer for the iOS app. Everything it returns is labelled "mode": "mock".

Speaks protocol v1 (docs/ios/protocol-draft.md), like the desktop apps: POST only, every reply signed with the
computer's key, pairing with a commitment, a token for reads, a counter and the phone's signature for writes, and
confirmations signed over the digest of what the phone shows. Replays the demo mission of ona-core (same plan, same two
offers); the payment uses digest version 2.

The phone pairs with a QR code (printed in the terminal as text; `--qr` also opens it as an image). The mock has no
screen: it prints the 6-digit code and confirms it itself.

Standard library only. Usage:
    python3 mock_computer.py [--port 8790] [--host 127.0.0.1] [--step-seconds 3] [--qr]
Use --host 0.0.0.0 to reach it from an iPhone on the same network.
"""

from __future__ import annotations

import argparse
import json
import socket
import secrets
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from chats import MAX_TEXT, Chat
import pairing as proto
from pairing import Pairing

MODE = "mock"

# Same values as ona-core's demo (DEMO_PLAN, MockWeb::demo, demo_policy).
DEMO_TITLE = "Find an employment lawyer"
DEMO_PLAN = ["search", "read", "read", "compare", "confirm_recipient", "contact",
             "prepare_payment", "confirm_payment", "pay"]
DEMO_OFFERS = [
    {"firm_id": "cabinet-a", "specialties": ["labour"], "price_cents": 90_000, "delay_days": 7,
     "source_spans": ["Consultation 900 euros, within 7 days"]},
    {"firm_id": "cabinet-b", "specialties": ["labour"], "price_cents": 60_000, "delay_days": 10,
     "source_spans": ["Flat fee 600 euros, within 10 days"]},
]
DIRECTORY = {"cabinet-a": "cabinet-a.testnet", "cabinet-b": "cabinet-b.testnet"}
DEMO_AMOUNT = 1_000_000_000_000_000_000_000_000  # 1 NEAR in yoctoNEAR, as in ona-core's `ona demo`

CONFIRM_STEPS = {"confirm_recipient": "recipient", "confirm_payment": "payment"}

# A simulated pool portfolio, shaped like ona-core's `pool_portfolio` reply (docs/desktop/pool-commands.md). Amounts in
# yoctoNEAR (1 NEAR = 10**24). Made up for the phone's Pool tab: no pool runs behind the mock.
NEAR = 10**24
# A share is a small unit: about 10**-6 NEAR when a vault starts, then its price follows the vault's gains or losses.
PRICE_0, PRICE_2 = 1_020_000 * 10**12, 995_000 * 10**12  # 0.00000102 and 0.000000995 NEAR per share
DEMO_PORTFOLIO = {
    "cash": {"tiers": [{"tier": 0, "note_value": str(NEAR), "held": 2, "spending": 0},
                       {"tier": 1, "note_value": str(NEAR // 10), "held": 3, "spending": 1}],
             "value": str(2 * NEAR + 3 * NEAR // 10), "spending_value": str(NEAR // 10), "awaiting_signature": 0},
    "vaults": [
        {"vault": 0, "share_price": str(PRICE_0), "frozen": False,
         "tiers": [{"tier": 0, "note_value": str(5_000_000 * PRICE_0), "held": 1, "spending": 0}],
         "value": str(5_000_000 * PRICE_0), "spending_value": "0", "awaiting_signature": 0},
        {"vault": 2, "share_price": str(PRICE_2), "frozen": True,
         "tiers": [{"tier": 0, "note_value": str(1_000_000 * PRICE_2), "held": 2, "spending": 0}],
         "value": str(2 * 1_000_000 * PRICE_2), "spending_value": "0", "awaiting_signature": 1},
    ],
    "vault_count": 3,
}
DEMO_PORTFOLIO["total"] = str(int(DEMO_PORTFOLIO["cash"]["value"]) + sum(int(v["value"]) for v in DEMO_PORTFOLIO["vaults"]))


NETWORK = "testnet"
CONTRACT = "mock-pay.ona.testnet"


def payment_screen(to: str, amount: int) -> str:
    return f"Pay {amount} yoctoNEAR to {to}"


class Mission:
    """A replay of the demo mission. The computer advances on its own and stops at each human confirmation."""

    def __init__(self):
        self.id = "m-" + secrets.token_hex(16)
        self.phase = "plan_proposed"
        self.cursor = 0  # index in DEMO_PLAN of the current step
        self.events: list[dict] = []
        self.chosen: str | None = None
        self.outputs: dict[str, int] = {}
        self.payments: list[dict] = []
        self.model_calls = 1  # the plan
        self._payment: dict | None = None
        self.pending = self._new_pending("plan", plan=list(DEMO_PLAN))
        self.log("Mission opened, plan proposed")

    # -- helpers ---------------------------------------------------------------------------------
    def log(self, text: str, tool: str | None = None) -> None:
        """`tool` names the step that produced the event (search, read, …); None for status lines."""
        self.events.append({"at": int(time.time()), "text": text, "tool": tool})

    def _new_pending(self, kind: str, **data) -> dict:
        """A confirmation with a random id and `content`, the digest of what the phone must show."""
        pending = {"id": "c-" + secrets.token_hex(16), "kind": kind, **data}
        if kind == "plan":
            pending["content"] = proto.plan_digest(pending["id"], data["plan"])
        elif kind == "recipient":
            pending["content"] = proto.offers_digest(pending["id"], data["offers"])
        else:
            pending["content"] = data["payment"]["digest"]
        return pending

    def _count(self, tool: str) -> None:
        self.outputs[tool] = self.outputs.get(tool, 0) + 1

    def payment(self) -> dict:
        """Prepared once per mission, with a fresh nonce: its digest changes from one payment to the next."""
        if self._payment is None:
            to, amount, nonce = DIRECTORY[self.chosen], str(DEMO_AMOUNT), proto.random_hex16()
            self._payment = {"to": to, "amount": amount, "screen": payment_screen(to, DEMO_AMOUNT),
                             "digest": proto.payment_digest(NETWORK, CONTRACT, self.id, nonce, to, amount),
                             "digest_version": 2, "network": NETWORK, "contract": CONTRACT, "mission_id": self.id,
                             "nonce": nonce}
        return self._payment

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
                self.log("Waiting: choice of firm")
            else:
                self.pending = self._new_pending("payment", payment=self.payment())
                self.log("Waiting: payment confirmation")
            self.phase = "waiting"
            return
        if step == "search":
            self._count("search")
            self.log("Search \"employment lawyer paris\": 2 results", "search")
        elif step == "read":
            n = DEMO_PLAN[: self.cursor + 1].count("read")
            self.model_calls += 1
            self._count("fetch")
            self.log(f"Reading page {n} of 2 (offer extracted)", "read")
        elif step == "compare":
            self.log("Comparison: 2 offers ranked", "compare")
        elif step == "contact":
            self._count("contact")
            self.log(f"Generic message sent to {self.chosen}", "contact")
        elif step == "prepare_payment":
            self.log("Payment prepared from the directory", "prepare_payment")
        elif step == "pay":
            p = self.payment()  # ona-core lists payments apart, not in "outputs"
            self.payments.append({"to": p["to"], "amount": p["amount"]})
            self.log(f"Payment sent: mock-tx-{p['digest'][:16]}", "pay")
        self.cursor += 1
        if self.cursor == len(DEMO_PLAN):
            self.phase = "closed"
            self.log("Mission finished, exposure report ready")

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
            self.log(f"Declined on the phone ({pending['kind']}): mission stopped")
            return None
        if pending["kind"] == "recipient":
            firm = body.get("firm")
            if firm not in DIRECTORY:
                return "unknown firm"
            self.chosen = firm
            self.log(f"Firm chosen on the phone: {firm}")
        elif pending["kind"] == "payment":
            if body.get("digest") != pending["payment"]["digest"]:
                return "payment digest does not match"
            self.log("Payment confirmed on the phone")
        else:
            self.log("Plan accepted on the phone")
        self.pending = None
        self.phase = "running"
        if pending["kind"] != "plan":
            self.cursor += 1  # the confirmation step itself is done
        return None

    # -- view ------------------------------------------------------------------------------------
    def plan_steps(self) -> list[str]:
        return list(DEMO_PLAN)

    def exposure(self) -> dict | None:
        if self.phase not in ("closed", "cancelled"):
            return None
        return {
                "outputs": self.outputs,
                "refused_by_gate": {},
                "firms_contacted": [self.chosen] if self.outputs.get("contact") else [],
                "payments": self.payments,
                "model_calls": self.model_calls,
                "mode": MODE,
            }


class Computer:
    def __init__(self, step_seconds: float, pairing: Pairing):
        self.pairing = pairing
        self.lock = threading.Lock()
        self.chats: dict[str, Chat] = {}
        self.step_seconds = step_seconds
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        while True:
            time.sleep(self.step_seconds)
            with self.lock:
                for chat in self.chats.values():
                    chat.tick()

    def _pending(self, confirmation_id) -> dict | None:
        for chat in self.chats.values():
            if chat.waits_for(confirmation_id):
                return chat.mission.pending
        return None

    def confirm(self, body: dict) -> str | None:
        with self.lock:
            pending = self._pending(body.get("id"))
        if pending is None:
            error = self.pairing.authorize(body)
            return error or ("replayed request" if body.get("id") in self.pairing.executed else "stale confirmation")
        # The phone signs the digest of what it showed; the computer puts the digest of what it asked.
        error = self.pairing.check_write(
            body, lambda pid, counter: proto.confirm_message(pid, counter, body, pending["content"]),
            confirmation=pending["id"])
        if error:
            print(f"   confirmation refused: {error}", flush=True)
            return error
        with self.lock:
            for chat in self.chats.values():
                if chat.waits_for(body.get("id")):
                    error = chat.confirm(body)
                    if error is None:
                        self.pairing.record_confirmation(pending["id"])
                    return error
        return "stale confirmation"

    def chat_list(self) -> dict:
        with self.lock:
            chats = sorted(self.chats.values(), key=lambda c: c.updated_at, reverse=True)
            return {"mode": MODE, "chats": [c.summary() for c in chats]}

    def chat_view(self, chat_id: str) -> dict | None:
        with self.lock:
            chat = self.chats.get(chat_id)
            return {"mode": MODE, "chat": chat.view()} if chat else None

    def create_chat(self, body: dict) -> tuple[str | None, str | None]:
        """Returns (error, chat_id)."""
        error = self.pairing.check_write(body, lambda pid, counter: proto.chat_message(pid, counter, None, body.get("text")))
        if error:
            return error, None
        text = _clean_text(body.get("text"))
        if text is None:
            return "empty or too long message", None
        with self.lock:
            chat = Chat(text, Mission)
            self.chats[chat.id] = chat
            return None, chat.id

    def post_message(self, chat_id: str, body: dict) -> str | None:
        error = self.pairing.check_write(body, lambda pid, counter: proto.chat_message(pid, counter, chat_id,
                                                                                         body.get("text")))
        if error:
            return error
        text = _clean_text(body.get("text"))
        if text is None:
            return "empty or too long message"
        with self.lock:
            chat = self.chats.get(chat_id)
            if chat is None:
                return "unknown chat"
            chat.message(text)
            return None

    def delete_chat(self, chat_id: str, body: dict) -> str | None:
        error = self.pairing.check_write(body, lambda pid, counter: proto.delete_message(pid, counter, chat_id))
        if error:
            return error
        with self.lock:
            return None if self.chats.pop(chat_id, None) else "unknown chat"


def _clean_text(text) -> str | None:
    if not isinstance(text, str):
        return None
    text = text.strip()
    return text if 0 < len(text) <= MAX_TEXT else None


def make_handler(computer: Computer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ona-mock-computer/1"

        def _raw(self, status: int, data: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def _send(self, status: int, payload: dict, nonce: str = "") -> None:
            """Every reply: {"reply": "<JSON text>", "signature": "<computer's signature>"}."""
            reply = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            signature = computer.pairing.sign_reply(nonce, self.path, status, reply.encode("utf-8"))
            self._raw(status, json.dumps({"reply": reply, "signature": signature}).encode("utf-8"))

        def _error(self, status: int, message: str, nonce: str = "") -> None:
            self._send(status, {"ok": False, "error": message, "mode": MODE}, nonce)

        def _ok(self, nonce: str, **data) -> None:
            self._send(200, {"ok": True, "mode": MODE, **data}, nonce)

        def do_GET(self):  # noqa: N802 (http.server naming)
            self._error(404, "not found")

        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            if length > 16_384:
                # Unreadable request: the only kind of reply left unsigned, always a failure.
                return self._raw(413, b'{"ok":false,"error":"body too large"}')
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                body = None
            if not isinstance(body, dict):
                return self._error(400, "body is not a JSON object")
            nonce = body.get("nonce") if isinstance(body.get("nonce"), str) and len(body["nonce"]) <= 64 else ""
            path = self.path
            if path == "/v1/pair":
                error, reply = computer.pairing.commit(body)
                return self._error(403, error, nonce) if error else self._ok(nonce, **reply)
            if path == "/v1/pair/reveal":
                error, reply, code = computer.pairing.reveal(body)
                if error:
                    print(f"   pairing refused: {error}", flush=True)
                    return self._error(403, error, nonce)
                print(f"==> Phone paired ({reply['pairing_id']}). Verification code: {code[:3]} {code[3:]} "
                      "(confirmed by the mock itself)", flush=True)
                return self._ok(nonce, **reply)
            if path == "/v1/pool/portfolio":
                # Read only, like the chats: the pool is operated and confirmed on the computer.
                error = computer.pairing.authorize(body)
                if error:
                    return self._error(403, error, nonce)
                return self._send(200, {"mode": MODE, "portfolio": DEMO_PORTFOLIO}, nonce)
            if path == "/v1/chats/list":
                error = computer.pairing.authorize(body)
                return self._error(403, error, nonce) if error else self._send(200, computer.chat_list(), nonce)
            parts = path.split("/")  # ["", "v1", "chats", "<id>", "view" | "messages" | "delete"]
            if len(parts) == 5 and parts[1:3] == ["v1", "chats"] and parts[4] == "view":
                error = computer.pairing.authorize(body)
                if error:
                    return self._error(403, error, nonce)
                view = computer.chat_view(parts[3])
                return self._send(200, view, nonce) if view else self._error(404, "unknown chat", nonce)
            if path == "/v1/confirm":
                error = computer.confirm(body)
                return self._error(_status(error), error, nonce) if error else self._ok(nonce)
            if path == "/v1/chats":
                error, chat_id = computer.create_chat(body)
                return self._error(_status(error), error, nonce) if error else self._ok(nonce, chat_id=chat_id)
            if len(parts) == 5 and parts[1:3] == ["v1", "chats"] and parts[4] in ("messages", "delete"):
                chat_id = parts[3]
                if parts[4] == "messages":
                    error = computer.post_message(chat_id, body)
                else:
                    error = computer.delete_chat(chat_id, body)
                return self._error(_status(error), error, nonce) if error else self._ok(nonce)
            self._error(404, "not found", nonce)

        def log_message(self, fmt, *args):  # one short line per request
            print(f"{self.command} {self.path} -> {args[1] if len(args) > 1 else ''}", flush=True)

    return Handler


def _status(error: str) -> int:
    """403 for a missing pairing or token, as the desktop apps; 409 for any other refused write."""
    return 403 if error in ("not paired", "missing or wrong token") else 409


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
    parser.add_argument("--address", help="address put in the pairing QR (default: guessed from --host)")
    parser.add_argument("--qr", action="store_true", help="also open the pairing QR as an image (macOS)")
    parser.add_argument("--onion", help="put this .onion address in the QR instead of a local address "
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
    pairing = Pairing("Simulated computer", address, onion)
    computer = Computer(args.step_seconds, pairing)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(computer))
    print(f"ONA mock computer (mode: mock, protocol v1) on http://{args.host}:{args.port}", flush=True)
    print_pairing(pairing, qr=args.qr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
