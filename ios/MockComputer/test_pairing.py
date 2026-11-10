"""Tests of the mock's P-256 code and of pairing / signed confirmations. Run: python3 -m unittest -v"""

import base64
import unittest

import p256
from pairing import CONFIRM_DOMAIN, PAIR_DOMAIN, Pairing, confirm_message, fields, sas

# RFC 6979, appendix A.2.5 (P-256, SHA-256, message "sample").
RFC_D = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
RFC_UX = 0x60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6
RFC_UY = 0x7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299
RFC_R = 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
RFC_S = 0xF7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8

# Produced by CryptoKit (P256.Signing, macOS) — see ios/ONA/ONATests/PairingTests.swift, `crossLanguageVector`.
SWIFT_PUBLIC_KEY = "BAyQHUI8gxyoXifHPCY7oTJyG7nXqExPA4CypnVv1gEzHIhwI03sh4UEwXQUT6SxS2amUWkWBtgXPlW9N+OBVp4="
SWIFT_MESSAGE_HEX = "0e0000006f6e612f636f6e6669726d2f763003000000702d3103000000632d330600000061636365707400000000020000006162"
SWIFT_SIGNATURE = "MEYCIQD0k1mmYvXAC4IWy6hNET+ZmTBAdqnrm+5gdIb1rIs7QgIhALKtYM/kYDAzqHau+ifTx8uJI9AdlkYaUn5w9w8M3AdK"
# Same inputs as `sasVector` in PairingTests.swift.
SAS_COMPUTER_KEY = bytes([4]) + bytes(range(1, 65))
SAS_PHONE_KEY = bytes([4]) + bytes(range(65, 129))
SAS_CODE = "c29tZS1jb2Rl"
SAS_EXPECTED = "093832"


def der(r: int, s: int) -> bytes:
    def i(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return b"\x02" + bytes([len(raw)]) + raw
    body = i(r) + i(s)
    return b"\x30" + bytes([len(body)]) + body


class P256Tests(unittest.TestCase):
    def test_rfc6979_public_key(self):
        self.assertEqual(p256.mul(RFC_D, p256.G), (RFC_UX, RFC_UY))

    def test_rfc6979_signature_verifies(self):
        public = p256.encode_x963((RFC_UX, RFC_UY))
        self.assertTrue(p256.verify(public, b"sample", der(RFC_R, RFC_S)))
        self.assertFalse(p256.verify(public, b"samplf", der(RFC_R, RFC_S)))
        self.assertFalse(p256.verify(public, b"sample", der(RFC_R, RFC_S ^ 1)))

    def test_sign_then_verify(self):
        d, public = p256.generate_keypair()
        signature = p256.sign(d, b"hello")
        self.assertTrue(p256.verify(public, b"hello", signature))
        self.assertFalse(p256.verify(public, b"hellp", signature))

    def test_rejects_points_off_the_curve(self):
        with self.assertRaises(ValueError):
            p256.decode_x963(b"\x04" + bytes(64))

    def test_cryptokit_signature_verifies(self):
        # The signed bytes must also be the ones the mock rebuilds from a confirmation body.
        self.assertEqual(SWIFT_MESSAGE_HEX, confirm_message("p-1", {"id": "c-3", "decision": "accept",
                                                                    "digest": "ab"}).hex())
        public = base64.b64decode(SWIFT_PUBLIC_KEY)
        message = bytes.fromhex(SWIFT_MESSAGE_HEX)
        self.assertTrue(p256.verify(public, message, base64.b64decode(SWIFT_SIGNATURE)))


class FieldsTests(unittest.TestCase):
    def test_layout(self):
        self.assertEqual(fields("ab", b"\x01", None), b"\x02\x00\x00\x00ab\x01\x00\x00\x00\x01\x00\x00\x00\x00")

    def test_sas_matches_swift(self):
        self.assertEqual(sas(SAS_COMPUTER_KEY, SAS_PHONE_KEY, SAS_CODE), SAS_EXPECTED)


class PairingFlowTests(unittest.TestCase):
    def setUp(self):
        self.computer = Pairing("Test", "http://127.0.0.1:8790")
        self.phone_d, self.phone_key = p256.generate_keypair()

    def pair_body(self, code=None, sign_with=None):
        code = code or self.computer.code
        message = fields(PAIR_DOMAIN, code, self.phone_key, self.computer.computer_key)
        signature = p256.sign(sign_with or self.phone_d, message)
        return {"code": code, "phone_key": base64.b64encode(self.phone_key).decode(),
                "signature": base64.b64encode(signature).decode()}

    def signed(self, body: dict, pairing_id: str, key=None) -> dict:
        body = dict(body, pairing_id=pairing_id)
        signature = p256.sign(key or self.phone_d, confirm_message(pairing_id, body))
        return dict(body, signature=base64.b64encode(signature).decode())

    def test_payload_round_trip(self):
        payload = self.computer.payload()
        self.assertTrue(payload.startswith("ona-pair:"))
        raw = payload[len("ona-pair:"):]
        import json
        data = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
        self.assertEqual(data["v"], 0)
        self.assertEqual(base64.b64decode(data["computer_key"]), self.computer.computer_key)
        self.assertEqual(data["code"], self.computer.code)

    def test_pairing_then_signed_confirmation(self):
        code = self.computer.code
        error, pairing_id, verification = self.computer.pair(self.pair_body())
        self.assertIsNone(error)
        self.assertEqual(verification, sas(self.computer.computer_key, self.phone_key, code))
        self.assertEqual(len(verification), 6)

        body = {"id": "c-3", "decision": "accept", "digest": "ab" * 32}
        self.assertIsNone(self.computer.check_confirmation(self.signed(body, pairing_id)))

    def test_code_is_single_use(self):
        body = self.pair_body()
        self.assertIsNone(self.computer.pair(body)[0])
        self.assertEqual(self.computer.pair(body)[0], "unknown or used pairing code")

    def test_pairing_needs_the_phone_key(self):
        other_d, _ = p256.generate_keypair()
        error = self.computer.pair(self.pair_body(sign_with=other_d))[0]
        self.assertEqual(error, "pairing signature does not verify")

    def test_confirmation_refusals(self):
        self.assertEqual(self.computer.check_confirmation({"id": "c-1"}), "not paired")
        _, pairing_id, _ = self.computer.pair(self.pair_body())
        body = {"id": "c-2", "decision": "accept", "firm": "cabinet-b"}
        signed = self.signed(body, pairing_id)

        self.assertIsNone(self.computer.check_confirmation(signed))
        self.assertEqual(self.computer.check_confirmation(dict(signed, firm="cabinet-a")), "signature does not verify")
        self.assertEqual(self.computer.check_confirmation(dict(signed, id="c-9")), "signature does not verify")
        self.assertEqual(self.computer.check_confirmation(dict(signed, pairing_id="p-x")), "unknown pairing")
        self.assertEqual(self.computer.check_confirmation(dict(signed, signature=None)),
                         "missing or malformed signature")
        other_d, _ = p256.generate_keypair()
        self.assertEqual(self.computer.check_confirmation(self.signed(body, pairing_id, key=other_d)),
                         "signature does not verify")

    def test_domains_differ(self):
        self.assertNotEqual(PAIR_DOMAIN, CONFIRM_DOMAIN)


if __name__ == "__main__":
    unittest.main()
