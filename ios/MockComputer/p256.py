"""Minimal P-256 (secp256r1) for the MOCK computer only: key generation, ECDSA-SHA256 verification, and
signing of the mock's replies (protocol v1).

Pure Python, standard library only, so the mock keeps no dependency. Not constant-time and not reviewed: never use it
for anything but this test server. The real computer (ona-core) will use an audited library.
"""

from __future__ import annotations

import hashlib
import secrets

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

Point = tuple[int, int] | None  # None is the point at infinity


def on_curve(pt: Point) -> bool:
    if pt is None:
        return False
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def mul(k: int, pt: Point) -> Point:
    result: Point = None
    addend = pt
    while k:
        if k & 1:
            result = add(result, addend)
        addend = add(addend, addend)
        k >>= 1
    return result


def encode_x963(pt: Point) -> bytes:
    assert pt is not None
    return b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")


def decode_x963(data: bytes) -> Point:
    """Uncompressed point (65 bytes, 0x04 prefix). Raises ValueError if not a valid curve point."""
    if len(data) != 65 or data[0] != 4:
        raise ValueError("expected a 65-byte uncompressed P-256 point")
    pt = (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
    if not on_curve(pt):
        raise ValueError("point is not on P-256")
    return pt


def generate_keypair() -> tuple[int, bytes]:
    """Returns (private scalar, public key in X9.63)."""
    d = secrets.randbelow(N - 1) + 1
    return d, encode_x963(mul(d, G))


def _der_int(data: bytes, i: int) -> tuple[int, int]:
    if data[i] != 0x02:
        raise ValueError("DER: expected INTEGER")
    length = data[i + 1]
    if length == 0 or length > 33:
        raise ValueError("DER: bad INTEGER length")
    start = i + 2
    return int.from_bytes(data[start:start + length], "big"), start + length


def decode_der_signature(der: bytes) -> tuple[int, int]:
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("DER: bad SEQUENCE")
    r, i = _der_int(der, 2)
    s, i = _der_int(der, i)
    if i != len(der):
        raise ValueError("DER: trailing bytes")
    return r, s


def verify(public_key_x963: bytes, message: bytes, der_signature: bytes, low_s: bool = False) -> bool:
    """ECDSA P-256 with SHA-256, as produced by CryptoKit's `P256.Signing` / `SecureEnclave.P256.Signing`."""
    try:
        q = decode_x963(public_key_x963)
        r, s = decode_der_signature(der_signature)
    except (ValueError, IndexError):
        return False
    if not (1 <= r < N and 1 <= s < N):
        return False
    if low_s and s > N // 2:  # protocol v1 refuses the high form
        return False
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    w = pow(s, -1, N)
    point = add(mul(e * w % N, G), mul(r * w % N, q))
    return point is not None and point[0] % N == r


def sign(d: int, message: bytes) -> bytes:
    """Signs for the mock only (random nonce from `secrets`, not constant time). Returns a DER signature in the
    low-s form (s ≤ n/2) that protocol v1 requires."""
    e = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        r = mul(k, G)[0] % N
        s = pow(k, -1, N) * (e + r * d) % N
        if r and s:
            break
    if s > N // 2:
        s = N - s

    def der_int(v: int) -> bytes:
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")  # leading 0x00 when the top bit is set
        return b"\x02" + bytes([len(raw)]) + raw

    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body
