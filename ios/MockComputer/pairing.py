"""Pairing and signed confirmations of the mock computer (docs/ios/protocol-draft.md, step 3)."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import struct
import threading

import p256

PAIR_DOMAIN = "ona/pair/v0"
CONFIRM_DOMAIN = "ona/confirm/v0"
SAS_DOMAIN = "ona/sas/v0"
PAYLOAD_PREFIX = "ona-pair:"


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


def sas(computer_key: bytes, phone_key: bytes, code: str) -> str:
    """6-digit verification code shown on both sides."""
    digest = hashlib.sha256(fields(SAS_DOMAIN, computer_key, phone_key, code)).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1_000_000:06d}"


def confirm_message(pairing_id: str, body: dict) -> bytes:
    return fields(CONFIRM_DOMAIN, pairing_id, body.get("id"), body.get("decision"), body.get("firm"),
                  body.get("digest"))


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64decode(text: str) -> bytes:
    """Standard base64, padding optional. Raises ValueError."""
    if not isinstance(text, str):
        raise ValueError("expected a base64 string")
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


class Pairing:
    """One computer key, one pending pairing code, at most one paired phone (enough for the mock)."""

    def __init__(self, name: str, address: str | None, onion: str | None = None):
        self.lock = threading.Lock()
        self.name = name
        self.address = address
        self.onion = onion
        self._private, self.computer_key = p256.generate_keypair()
        self.code = b64url(secrets.token_bytes(16))
        self.phone_key: bytes | None = None
        self.pairing_id: str | None = None
        self.count = 0

    def payload(self) -> str:
        """Text of the pairing QR code."""
        data = {"v": 0, "name": self.name, "address": self.address, "onion": self.onion,
                "computer_key": base64.b64encode(self.computer_key).decode("ascii"), "code": self.code}
        return PAYLOAD_PREFIX + b64url(json.dumps(data, separators=(",", ":")).encode("utf-8"))

    def pair(self, body: dict) -> tuple[str | None, str | None, str | None]:
        """Returns (error, pairing_id, sas)."""
        with self.lock:
            if not self.code or body.get("code") != self.code:
                return "unknown or used pairing code", None, None
            try:
                phone_key = b64decode(body.get("phone_key"))
                signature = b64decode(body.get("signature"))
                p256.decode_x963(phone_key)
            except ValueError as e:
                return f"bad phone key or signature: {e}", None, None
            message = fields(PAIR_DOMAIN, self.code, phone_key, self.computer_key)
            if not p256.verify(phone_key, message, signature):
                return "pairing signature does not verify", None, None
            code = self.code
            self.code = ""  # single use
            self.count += 1
            self.phone_key = phone_key
            self.pairing_id = f"p-{self.count}-{b64url(secrets.token_bytes(6))}"
            return None, self.pairing_id, sas(self.computer_key, phone_key, code)

    def check_confirmation(self, body: dict) -> str | None:
        """Error message, or None if the confirmation is signed by the paired phone."""
        with self.lock:
            if self.phone_key is None or self.pairing_id is None:
                return "not paired"
            if body.get("pairing_id") != self.pairing_id:
                return "unknown pairing"
            try:
                signature = b64decode(body.get("signature"))
            except ValueError:
                return "missing or malformed signature"
            if not p256.verify(self.phone_key, confirm_message(self.pairing_id, body), signature):
                return "signature does not verify"
            return None

    def new_code(self) -> None:
        """Forgets the paired phone and issues a new pairing code."""
        with self.lock:
            self.code = b64url(secrets.token_bytes(16))
            self.phone_key = None
            self.pairing_id = None
