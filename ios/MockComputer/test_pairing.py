"""Tests of the mock's P-256 code and of protocol v1 bytes and pairing. Run: python3 -m unittest -v"""

import base64
import hashlib
import unittest
from unittest import mock

import p256
import pairing as proto
from pairing import Pairing

# RFC 6979, appendix A.2.5 (P-256, SHA-256, message "sample"). Its s is above n/2: a high-s signature.
RFC_D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC_UX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC_UY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
RFC_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

# Vectors shared with the desktop apps and the iPhone app (protocol v1).
COMPUTER_KEY = bytes([4]) + bytes(range(1, 65))
PHONE_KEY = bytes([4]) + bytes(range(65, 129))
PHONE_NONCE = "00112233445566778899aabbccddeeff"
COMPUTER_NONCE = "ffeeddccbbaa99887766554433221100"
CODE = "c29tZS1jb2Rl"
PAIRING_ID = "p-0123456789abcdef0123456789abcdef"
# Signature made by the Rust desktop app (p256 crate, RFC 6979) with the private key 0x07…07.
RUST_PUBLIC_KEY = "BB4YUy/UdUwC8wQdnHXOszuD/9gax85P6ILMscmLxYlupGwxHE4v9A3ZajZT5uRURdMt/khuztdcepDGoYiBwKM="
RUST_SIGNATURE = "MEUCIQCKpmfTBH6QHkQjK+2OSErWZ8NWVddjujyvnAIvA9OSSAIgPYwZ31pcNKYUz59ysuap+EQESYYeUfOI8n8sUxE/SHU="


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def der(r: int, s: int) -> bytes:
    def i(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(raw)]) + raw
    body = i(r) + i(s)
    return b"\x30" + bytes([len(body)]) + body


class P256Tests(unittest.TestCase):
    def test_rfc6979_public_key(self):
        self.assertEqual(p256.mul(RFC_D, p256.G), (RFC_UX, RFC_UY))

    def test_rfc6979_signature_verifies_but_is_high_s(self):
        public = p256.encode_x963((RFC_UX, RFC_UY))
        self.assertTrue(p256.verify(public, b"sample", der(RFC_R, RFC_S)))
        self.assertFalse(p256.verify(public, b"samplf", der(RFC_R, RFC_S)))
        # Protocol v1 refuses the high form, and accepts the low one.
        self.assertFalse(p256.verify(public, b"sample", der(RFC_R, RFC_S), low_s=True))
        self.assertTrue(p256.verify(public, b"sample", der(RFC_R, p256.N - RFC_S), low_s=True))

    def test_signatures_are_low_s(self):
        d, public = p256.generate_keypair()
        for _ in range(8):
            signature = p256.sign(d, b"hello")
            self.assertTrue(p256.verify(public, b"hello", signature, low_s=True))
            self.assertFalse(p256.verify(public, b"hellp", signature, low_s=True))

    def test_rejects_points_off_the_curve(self):
        with self.assertRaises(ValueError):
            p256.decode_x963(b"\x04" + bytes(64))

    def test_rust_signature_verifies(self):
        message = proto.confirm_message(PAIRING_ID, 7, {"id": "c-1", "decision": "accept", "digest": "ab"}, "cd")
        public = base64.b64decode(RUST_PUBLIC_KEY)
        self.assertEqual(p256.encode_x963(p256.mul(int.from_bytes(b"\x07" * 32, "big"), p256.G)), public)
        self.assertTrue(p256.verify(public, message, base64.b64decode(RUST_SIGNATURE), low_s=True))
        self.assertFalse(p256.verify(public, message + b"\x00", base64.b64decode(RUST_SIGNATURE), low_s=True))


class VectorTests(unittest.TestCase):
    def test_layout(self):
        self.assertEqual(proto.fields("ab", b"\x01", None), b"\x02\x00\x00\x00ab\x01\x00\x00\x00\x01\x00\x00\x00\x00")

    def test_pairing(self):
        self.assertEqual(proto.commitment(PHONE_KEY, PHONE_NONCE),
                         "6c2ee677c6aa3c2c1721f781e55f7e223caf87d729cc5e68bd6414de0a17bb7b")
        self.assertEqual(proto.sas(COMPUTER_KEY, PHONE_KEY, CODE, PHONE_NONCE, COMPUTER_NONCE), "587047")
        self.assertEqual(sha(proto.pair_message(PAIRING_ID, CODE, PHONE_KEY, COMPUTER_KEY, PHONE_NONCE,
                                                COMPUTER_NONCE)),
                         "3332d89e36dd9adeb88e8f5f18861d92fdcc048357c78bc7c7ed6284c1a069cd")

    def test_writes(self):
        self.assertEqual(sha(proto.confirm_message(PAIRING_ID, 7, {"id": "c-1", "decision": "accept", "digest": "ab"},
                                                   "cd")),
                         "1c61312dbd420b5f78b85dc82cf6f3c505386043f9704f4cd087f882a9389139")
        self.assertEqual(sha(proto.chat_message(PAIRING_ID, 8, None, "hello")),
                         "bbd789ac3408fd211ada877e56cdc981f0d37ce8c6ba1f115d7d92ec2b5f8634")
        self.assertEqual(sha(proto.delete_message(PAIRING_ID, 9, "chat-1")),
                         "ee3c7db20a817bb5c643f005a052fbf5af413ce9780a6fa31f3acc0e91ed959c")

    def test_reply(self):
        self.assertEqual(sha(proto.reply_message(PHONE_NONCE, "POST", "/v1/chats/list", 200, b'{"ok":true}')),
                         "c9e6dc8eb32a3f5a97b226281a3151a023754cf518c0828468f3b25dd4e855b0")

    def test_digests(self):
        self.assertEqual(proto.plan_digest("c-1", ["search", "read"]),
                         "10b2ecd6ff60485e505b911709ed14b162137f0237abaa8aed21eee7c26edb84")
        offer = {"firm_id": "cabinet-b", "price_cents": 60000, "delay_days": 10,
                 "source_spans": ["Flat fee 600 euros, within 10 days"]}
        self.assertEqual(proto.offers_digest("c-2", [offer]),
                         "1335a1d0959d1c26f748ad05c45f86544f82830315a1c56fd72feb93be264c07")
        self.assertEqual(proto.payment_digest("testnet", "pay.ona.testnet", "m-1", PHONE_NONCE, "cabinet-b.testnet",
                                              "1000000000000000000000000"),
                         "ee00b991ccc819a4b64630c245ae7e281ef98d74f0eb971b1ff4dd9290957950")

    def test_counters(self):
        self.assertEqual(proto.valid_counter(1), 1)
        self.assertEqual(proto.valid_counter(proto.MAX_COUNTER), proto.MAX_COUNTER)
        for bad in (0, -1, proto.MAX_COUNTER + 1, 1.0, "1", True, None):
            self.assertIsNone(proto.valid_counter(bad), bad)


class Phone:
    """What the iPhone app does, in Python."""

    def __init__(self):
        self.d, self.key = p256.generate_keypair()
        self.nonce = proto.random_hex16()
        self.pairing_id = self.token = None
        self.counter = 0

    def sign(self, message: bytes) -> str:
        return base64.b64encode(p256.sign(self.d, message)).decode("ascii")

    def pair(self, computer: Pairing) -> str:
        code = computer.code
        error, committed = computer.commit({"code": code, "commitment": proto.commitment(self.key, self.nonce)})
        assert error is None, error
        message = proto.pair_message(committed["pairing_id"], code, self.key, computer.computer_key, self.nonce,
                                     committed["computer_nonce"])
        error, revealed, sas = computer.reveal({
            "pairing_id": committed["pairing_id"], "phone_key": base64.b64encode(self.key).decode("ascii"),
            "phone_nonce": self.nonce, "signature": self.sign(message)})
        assert error is None, error
        self.pairing_id, self.token = revealed["pairing_id"], revealed["token"]
        assert sas == proto.sas(computer.computer_key, self.key, code, self.nonce, committed["computer_nonce"])
        return sas

    def write(self, signed, **body) -> dict:
        self.counter += 1
        return {**body, "token": self.token, "pairing_id": self.pairing_id, "counter": self.counter,
                "signature": self.sign(signed(self.pairing_id, self.counter))}


class PairingFlowTests(unittest.TestCase):
    def setUp(self):
        self.computer = Pairing("Test Mac", "http://computer.test:8790")

    def test_payload(self):
        payload = self.computer.payload()
        self.assertTrue(payload.startswith(proto.PAYLOAD_PREFIX))
        raw = payload[len(proto.PAYLOAD_PREFIX):]
        data = __import__("json").loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        self.assertEqual(data["v"], 1)
        self.assertEqual(data["code"], self.computer.code)
        self.assertGreater(data["expires_at"], 0)

    def test_commit_reveal_then_signed_writes(self):
        phone = Phone()
        phone.pair(self.computer)
        self.assertIsNone(self.computer.authorize({"token": phone.token}))
        body = phone.write(lambda pid, c: proto.chat_message(pid, c, None, "hello"), text="hello")
        signed = lambda pid, c: proto.chat_message(pid, c, None, body["text"])  # noqa: E731
        self.assertIsNone(self.computer.check_write(body, signed))
        # The same request again, or an old counter: refused.
        self.assertEqual(self.computer.check_write(body, signed), "replayed request")
        forged = dict(body, text="pay everything")
        forged["counter"] = 9
        self.assertEqual(self.computer.check_write(forged, lambda pid, c: proto.chat_message(pid, c, None, "pay everything")),
                         "signature does not verify")

    def test_code_is_single_use_and_expires(self):
        phone = Phone()
        code = self.computer.code
        phone.pair(self.computer)
        error, _ = self.computer.commit({"code": code, "commitment": "0" * 64})
        self.assertEqual(error, "unknown or used pairing code")
        self.computer.new_code()
        with mock.patch("pairing.time.time", return_value=self.computer.expires_at + 1):
            error, _ = self.computer.commit({"code": self.computer.code, "commitment": "0" * 64})
        self.assertEqual(error, "expired pairing code")

    def test_reveal_must_match_the_commitment(self):
        phone, other = Phone(), Phone()
        code = self.computer.code
        _, committed = self.computer.commit({"code": code, "commitment": proto.commitment(phone.key, phone.nonce)})
        message = proto.pair_message(committed["pairing_id"], code, other.key, self.computer.computer_key,
                                     other.nonce, committed["computer_nonce"])
        error, _, _ = self.computer.reveal({"pairing_id": committed["pairing_id"],
                                            "phone_key": base64.b64encode(other.key).decode(),
                                            "phone_nonce": other.nonce, "signature": other.sign(message)})
        self.assertEqual(error, "pairing commitment does not match")
        self.assertIsNone(self.computer.token)

    def test_reads_need_the_token(self):
        self.assertEqual(self.computer.authorize({"token": "x"}), "not paired")
        phone = Phone()
        phone.pair(self.computer)
        self.assertEqual(self.computer.authorize({"token": "x"}), "missing or wrong token")


if __name__ == "__main__":
    unittest.main()
