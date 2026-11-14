"""Pairing, signed requests and signed replies of the mock computer, protocol v1 (docs/ios/protocol-draft.md).

Same bytes as the desktop apps (desktop/tauri/src-tauri/src/protocol.rs, desktop/ONADesktop/Core/Protocol) and the
iPhone app (ios/ONA/ONA/Pairing/SignedFields.swift): the tests share vectors.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import threading
import time

import p256

COMMIT_DOMAIN = "ona/pair-commit/v1"
PAIR_DOMAIN = "ona/pair/v1"
SAS_DOMAIN = "ona/sas/v1"
REPLY_DOMAIN = "ona/reply/v1"
CONFIRM_DOMAIN = "ona/confirm/v1"
MESSAGE_DOMAIN = "ona/message/v1"
DELETE_DOMAIN = "ona/delete/v1"
PLAN_DOMAIN = "ona/plan/v1"
OFFERS_DOMAIN = "ona/offers/v1"
PAY_DOMAIN = "ona/pay/v2"
PAYLOAD_PREFIX = "ona-pair:"
CODE_LIFETIME = 600          # seconds a pairing code is valid
REVEAL_WINDOW = 120          # seconds between commitment and reveal
MAX_COUNTER = 9_007_199_254_740_991


def fields(*items: str | bytes | None) -> bytes:
    """Each field: u32 little-endian length, then its bytes (text as UTF-8, None as empty)."""
    out = bytearray()
    for item in items:
        if item is None:
            raw = b""
        elif isinstance(item, (bytes, bytearray)):
            raw = bytes(item)
        else:
            raw = str(item).encode("utf-8")
        out += struct.pack("<I", len(raw)) + raw
    return bytes(out)


def sha_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def random_hex16() -> str:
    return secrets.token_hex(16)


def commitment(phone_key: bytes, phone_nonce: str) -> str:
    return sha_hex(fields(COMMIT_DOMAIN, phone_key, phone_nonce))


def pair_message(pairing_id: str, code: str, phone_key: bytes, computer_key: bytes, phone_nonce: str,
                 computer_nonce: str) -> bytes:
    return fields(PAIR_DOMAIN, pairing_id, code, phone_key, computer_key, phone_nonce, computer_nonce)


def sas(computer_key: bytes, phone_key: bytes, code: str, phone_nonce: str, computer_nonce: str) -> str:
    """6-digit verification code shown on both sides."""
    digest = hashlib.sha256(fields(SAS_DOMAIN, computer_key, phone_key, code, phone_nonce, computer_nonce)).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def confirm_message(pairing_id: str, counter: int, body: dict, content: str) -> bytes:
    return fields(CONFIRM_DOMAIN, pairing_id, str(counter), body.get("id"), body.get("decision"), body.get("firm"),
                  body.get("digest"), content)


def chat_message(pairing_id: str, counter: int, chat_id: str | None, text: str | None) -> bytes:
    """A message sent to the agent: new chat when chat_id is empty."""
    return fields(MESSAGE_DOMAIN, pairing_id, str(counter), chat_id, text)


def delete_message(pairing_id: str, counter: int, chat_id: str) -> bytes:
    return fields(DELETE_DOMAIN, pairing_id, str(counter), chat_id)


def reply_message(nonce: str, method: str, path: str, status: int, reply: bytes) -> bytes:
    return fields(REPLY_DOMAIN, nonce, method, path, str(status), reply)


def plan_digest(confirmation_id: str, steps: list[str]) -> str:
    return sha_hex(fields(PLAN_DOMAIN, confirmation_id, str(len(steps)), *steps))


def offers_digest(confirmation_id: str, offers: list[dict]) -> str:
    items: list[str] = [OFFERS_DOMAIN, confirmation_id, str(len(offers))]
    for offer in offers:
        spans = offer["source_spans"]
        items += [offer["firm_id"], str(offer["price_cents"]), str(offer["delay_days"]), str(len(spans)), *spans]
    return sha_hex(fields(*items))


def payment_digest(network: str, contract: str, mission_id: str, nonce: str, to: str, amount: str) -> str:
    """Digest version 2, the bytes of ona-core's payment gate."""
    return sha_hex(fields(PAY_DOMAIN, network, contract, mission_id, nonce, to, amount))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    """Standard base64, padding optional. Raises ValueError."""
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def valid_counter(value) -> int | None:
    """A JSON integer from 1 to 2^53 − 1: `1.0`, `"1"` and `true` are refused."""
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_COUNTER:
        return None
    return value


class Pairing:
    """One computer key, one pairing code, at most one paired phone (enough for the mock).

    The mock has no screen to click "The codes match": it prints the code and confirms it itself.
    """

    def __init__(self, name: str, address: str | None, onion: str | None = None):
        self.lock = threading.Lock()
        self.name = name
        self.address = address
        self.onion = onion
        self._private, self.computer_key = p256.generate_keypair()
        self.phone_key: bytes | None = None
        self.pairing_id: str | None = None
        self.token: str | None = None
        self.last_counter = 0
        self.executed: set[str] = set()   # confirmation ids already executed
        self._commit: dict | None = None
        self.new_code()

    def payload(self) -> str:
        """Text of the pairing QR code."""
        data = {"v": 1, "name": self.name, "address": self.address, "onion": self.onion,
                "computer_key": base64.b64encode(self.computer_key).decode("ascii"), "code": self.code,
                "expires_at": self.expires_at}
        return PAYLOAD_PREFIX + b64url(json.dumps(data, separators=(",", ":")).encode("utf-8"))

    def new_code(self) -> None:
        """Forgets the paired phone and issues a new pairing code."""
        self.code = b64url(secrets.token_bytes(16))
        self.expires_at = int(time.time()) + CODE_LIFETIME
        self.phone_key = self.pairing_id = self.token = None
        self.last_counter = 0
        self.executed = set()
        self._commit = None

    # -- replies -------------------------------------------------------------------------------------
    def sign_reply(self, nonce: str, path: str, status: int, reply: bytes) -> str:
        der = p256.sign(self._private, reply_message(nonce, "POST", path, status, reply))
        return base64.b64encode(der).decode("ascii")

    # -- pairing -------------------------------------------------------------------------------------
    def commit(self, body: dict) -> tuple[str | None, dict | None]:
        """`POST /v1/pair`. Returns (error, reply). The code is consumed whatever happens next."""
        with self.lock:
            if not self.code or not secrets.compare_digest(str(body.get("code", "")), self.code):
                return "unknown or used pairing code", None
            if time.time() > self.expires_at:
                self.new_code()
                return "expired pairing code", None
            value = body.get("commitment")
            if not isinstance(value, str) or len(value) != 64:
                return "bad request", None
            self.code_used = self.code
            self.code = ""
            self._commit = {"pairing_id": "p-" + random_hex16(), "computer_nonce": random_hex16(),
                            "commitment": value, "at": time.time(), "code": self.code_used}
            return None, {"pairing_id": self._commit["pairing_id"], "computer_nonce": self._commit["computer_nonce"]}

    def reveal(self, body: dict) -> tuple[str | None, dict | None, str | None]:
        """`POST /v1/pair/reveal`. Returns (error, reply, verification code). One attempt per commitment."""
        with self.lock:
            commit, self._commit = self._commit, None
            if commit is None or body.get("pairing_id") != commit["pairing_id"]:
                return "unknown pairing", None, None
            if time.time() - commit["at"] > REVEAL_WINDOW:
                self.new_code()
                return "expired pairing code", None, None
            try:
                phone_key = b64decode(body.get("phone_key"))
                p256.decode_x963(phone_key)
                signature = b64decode(body.get("signature"))
            except ValueError:
                self.new_code()
                return "missing or malformed signature", None, None
            phone_nonce = body.get("phone_nonce")
            if not isinstance(phone_nonce, str) or commitment(phone_key, phone_nonce) != commit["commitment"]:
                self.new_code()
                return "pairing commitment does not match", None, None
            message = pair_message(commit["pairing_id"], commit["code"], phone_key, self.computer_key, phone_nonce,
                                   commit["computer_nonce"])
            if not p256.verify(phone_key, message, signature, low_s=True):
                self.new_code()
                return "pairing signature does not verify", None, None
            self.phone_key = phone_key
            self.pairing_id = commit["pairing_id"]
            self.token = b64url(secrets.token_bytes(32))
            self.last_counter = 0
            code = sas(self.computer_key, phone_key, commit["code"], phone_nonce, commit["computer_nonce"])
            return None, {"pairing_id": self.pairing_id, "token": self.token}, code

    # -- requests ------------------------------------------------------------------------------------
    def authorize(self, body: dict) -> str | None:
        """Reads need the token."""
        with self.lock:
            if self.token is None:
                return "not paired"
            if not secrets.compare_digest(str(body.get("token", "")), self.token):
                return "missing or wrong token"
            return None

    def check_write(self, body: dict, signed_bytes, confirmation: str | None = None) -> str | None:
        """Token, pairing id, a counter above the last one, the phone's signature. The counter is recorded before
        the request runs, so a replayed request is refused even if it failed later."""
        error = self.authorize(body)
        if error:
            return error
        with self.lock:
            if body.get("pairing_id") != self.pairing_id:
                return "unknown pairing"
            counter = valid_counter(body.get("counter"))
            if counter is None or counter <= self.last_counter:
                return "replayed request"
            if confirmation is not None and confirmation in self.executed:
                return "replayed request"
            self.last_counter = counter
            try:
                signature = b64decode(body.get("signature"))
            except ValueError:
                return "missing or malformed signature"
            if not p256.verify(self.phone_key, signed_bytes(self.pairing_id, counter), signature, low_s=True):
                return "signature does not verify"
            return None

    def record_confirmation(self, confirmation_id: str) -> None:
        with self.lock:
            self.executed.add(confirmation_id)
