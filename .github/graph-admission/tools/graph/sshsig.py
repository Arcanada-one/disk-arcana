#!/usr/bin/env python3
"""AUP-GRAPH-006 `gate2b` — verify an SSHSIG detached signature. Python 3.12 stdlib only.

Why this file exists. `GraphAdmissionBundle/v1` travels into a caller repository as vendored bytes
with a `BUNDLE.json` of per-file sha256. That manifest is a TRIPWIRE, not a signature: a pull request
that rewrites a tool *and* its `BUNDLE.json` entry keeps the hashes consistent, and only
`BUNDLE_MODIFIED_BY_PR` (a diff-shape rule, not a cryptographic one) catches it. gate2b adds the
cryptographic half: `BUNDLE.json` is signed in the program repository with an Ed25519 SSH key, the
PUBLIC key travels with the bundle, and the gate verifies the detached signature before it trusts a
single byte of the bundle.

Why the verifier is written here instead of shelling out to `ssh-keygen -Y verify`:
  * the gate runs on whatever runner the caller has; a shell-out is a runtime dependency and a
    silent-skip risk (a missing binary must never degrade to "assume valid"). This has none;
  * the tools of this portion are stdlib-only and deterministic by rule.
The implementation is not trusted on its own word: `--selftest` cross-checks it against the real
`ssh-keygen -Y sign` / `-Y verify` on any host that has OpenSSH, over a matrix of positive and
negative fixtures, and records `not_measured` where the binary is absent instead of claiming a pass.

SSHSIG wire format (PROTOCOL.sshsig, OpenSSH):
    armor      "-----BEGIN SSH SIGNATURE-----" <base64> "-----END SSH SIGNATURE-----"
    blob       MAGIC "SSHSIG" | uint32 version | string publickey | string namespace
               | string reserved | string hash_algorithm | string signature
    signed     MAGIC "SSHSIG" | string namespace | string reserved | string hash_algorithm
               | string H(message)
    publickey  string "ssh-ed25519" | string A            (32 bytes)
    signature  string "ssh-ed25519" | string sig          (64 bytes)
Only `ssh-ed25519` is accepted. An RSA or ECDSA signature is REFUSED, not ignored: silently accepting
a weaker algorithm chosen by the signature file is the classic downgrade.
"""
from __future__ import annotations

import base64
import hashlib
import struct

MAGIC = b"SSHSIG"
SUPPORTED_KEY_TYPE = "ssh-ed25519"
SUPPORTED_HASHES = {"sha512": hashlib.sha512, "sha256": hashlib.sha256}

# ------------------------------------------------------------------ Ed25519 (RFC 8032) verification
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    """x from y on -x^2 + y^2 = 1 + d x^2 y^2, with the requested low bit. None if y is not on the curve."""
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None
    if x % 2 != sign:
        x = _P - x
    return x


# extended homogeneous coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z
def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * t1 * t2 * _D) % _P
    d = (2 * z1 * z2) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P


def _scalar_mul(p, e: int):
    q = (0, 1, 1, 0)  # neutral
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        e >>= 1
    return q


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)


def _decode_point(b: bytes):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return x, y, 1, (x * y) % _P


def _equal(p, q) -> bool:
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032 §5.1.7 verification. Returns False on every malformed input — never raises."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a = _decode_point(public_key)
    if a is None:
        return False
    r = _decode_point(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:  # non-canonical S: the classic malleability, refused
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % _L
    return _equal(_scalar_mul(_B, s), _point_add(r, _scalar_mul(a, h)))


# ------------------------------------------------------------------ SSH wire strings
def _read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise ValueError("truncated ssh string length")
    (n,) = struct.unpack(">I", buf[off:off + 4])
    off += 4
    if off + n > len(buf):
        raise ValueError("truncated ssh string body")
    return buf[off:off + n], off + n


def _string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def parse_armored(text: str) -> bytes:
    begin = "-----BEGIN SSH SIGNATURE-----"
    end = "-----END SSH SIGNATURE-----"
    if begin not in text or end not in text:
        raise ValueError("not an armored SSH signature")
    body = text.split(begin, 1)[1].split(end, 1)[0]
    return base64.b64decode("".join(body.split()))


def parse_public_key(line: str) -> tuple[str, bytes]:
    """An `ssh-ed25519 AAAA… comment` line → (type, 32-byte A)."""
    parts = line.split()
    if len(parts) < 2:
        raise ValueError("not an ssh public key line")
    blob = base64.b64decode(parts[1])
    kt, off = _read_string(blob, 0)
    if kt.decode() != parts[0]:
        raise ValueError(f"key type mismatch: line says {parts[0]!r}, blob says {kt.decode()!r}")
    a, off = _read_string(blob, off)
    return kt.decode(), a


def verify_detached(message: bytes, armored_signature: str, public_key_line: str,
                    expected_namespace: str) -> tuple[bool, str, dict]:
    """→ (ok, reason, details). `ok` is True only when everything below holds."""
    d: dict = {"namespace": None, "key_type": None, "hash_algorithm": None,
               "signature_key_fingerprint": None, "public_key_fingerprint": None}
    try:
        blob = parse_armored(armored_signature)
    except (ValueError, base64.binascii.Error) as e:
        return False, f"SIGNATURE_MALFORMED: {e}", d
    if not blob.startswith(MAGIC):
        return False, "SIGNATURE_MALFORMED: missing SSHSIG magic", d
    off = len(MAGIC)
    try:
        (version,) = struct.unpack(">I", blob[off:off + 4])
        off += 4
        pk_blob, off = _read_string(blob, off)
        namespace, off = _read_string(blob, off)
        reserved, off = _read_string(blob, off)
        hash_alg, off = _read_string(blob, off)
        sig_blob, off = _read_string(blob, off)
    except (ValueError, struct.error) as e:
        return False, f"SIGNATURE_MALFORMED: {e}", d
    if version != 1:
        return False, f"SIGNATURE_MALFORMED: unsupported SSHSIG version {version}", d

    d["namespace"] = namespace.decode(errors="replace")
    d["hash_algorithm"] = hash_alg.decode(errors="replace")
    if d["namespace"] != expected_namespace:
        return False, (f"SIGNATURE_WRONG_NAMESPACE: signed for {d['namespace']!r}, this gate only accepts "
                       f"{expected_namespace!r} — a signature made for another purpose is not a signature "
                       f"for this one"), d
    if d["hash_algorithm"] not in SUPPORTED_HASHES:
        return False, f"SIGNATURE_UNSUPPORTED_HASH: {d['hash_algorithm']!r}", d

    try:
        kt_sig, o2 = _read_string(pk_blob, 0)
        a_sig, _ = _read_string(pk_blob, o2)
        kt_s, o3 = _read_string(sig_blob, 0)
        raw_sig, _ = _read_string(sig_blob, o3)
    except ValueError as e:
        return False, f"SIGNATURE_MALFORMED: {e}", d
    d["key_type"] = kt_sig.decode(errors="replace")
    if d["key_type"] != SUPPORTED_KEY_TYPE or kt_s.decode(errors="replace") != SUPPORTED_KEY_TYPE:
        return False, (f"SIGNATURE_KEY_TYPE_REFUSED: {d['key_type']!r} — only {SUPPORTED_KEY_TYPE} is accepted; "
                       f"accepting whatever algorithm the signature file names is a downgrade"), d
    d["signature_key_fingerprint"] = fingerprint(kt_sig.decode(), a_sig)

    try:
        kt_pub, a_pub = parse_public_key(public_key_line)
    except (ValueError, base64.binascii.Error) as e:
        return False, f"PUBLIC_KEY_MALFORMED: {e}", d
    if kt_pub != SUPPORTED_KEY_TYPE:
        return False, f"PUBLIC_KEY_TYPE_REFUSED: {kt_pub!r}", d
    d["public_key_fingerprint"] = fingerprint(kt_pub, a_pub)
    if a_pub != a_sig:
        return False, ("SIGNATURE_KEY_MISMATCH: the signature was made by "
                       f"{d['signature_key_fingerprint']}, the trusted key is "
                       f"{d['public_key_fingerprint']}"), d

    h = SUPPORTED_HASHES[d["hash_algorithm"]](message).digest()
    signed = MAGIC + _string(namespace) + _string(reserved) + _string(hash_alg) + _string(h)
    if not ed25519_verify(a_pub, signed, raw_sig):
        return False, ("SIGNATURE_INVALID: the Ed25519 signature does not verify over this message — the "
                       "signed bytes are not these bytes"), d
    return True, "SIGNATURE_VALID", d


def fingerprint(key_type: str, a: bytes) -> str:
    blob = _string(key_type.encode()) + _string(a)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


# ------------------------------------------------------------------ signing (fixtures + selftest only)
# The PRODUCTION signature is produced by `ssh-keygen -Y sign` on the signing host, from a key that
# never enters a repository. These two functions exist so that the mutation battery can build its own
# signed fixtures WITHOUT depending on an OpenSSH binary being installed — a battery that silently
# skips when a tool is missing is a battery that reports a pass it did not measure. `--selftest` then
# cross-checks this implementation against the real `ssh-keygen` wherever that binary does exist.
def ed25519_keypair(seed: bytes) -> tuple[bytes, bytes]:
    """RFC 8032 §5.1.5: a 32-byte seed → (seed, 32-byte public key A)."""
    if len(seed) != 32:
        raise ValueError("an ed25519 seed is 32 bytes")
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(bytes(h[:32]), "little")
    x, y, z, _ = _scalar_mul(_B, a)
    zi = pow(z, _P - 2, _P)
    x, y = (x * zi) % _P, (y * zi) % _P
    return seed, (y | ((x & 1) << 255)).to_bytes(32, "little")


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    _, pub = ed25519_keypair(seed)
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(bytes(h[:32]), "little")
    r = int.from_bytes(hashlib.sha512(bytes(h[32:]) + message).digest(), "little") % _L
    x, y, z, _ = _scalar_mul(_B, r)
    zi = pow(z, _P - 2, _P)
    x, y = (x * zi) % _P, (y * zi) % _P
    rb = (y | ((x & 1) << 255)).to_bytes(32, "little")
    k = int.from_bytes(hashlib.sha512(rb + pub + message).digest(), "little") % _L
    s = (r + k * a) % _L
    return rb + s.to_bytes(32, "little")


def public_key_line(pub: bytes, comment: str = "fixture") -> str:
    blob = _string(SUPPORTED_KEY_TYPE.encode()) + _string(pub)
    return f"{SUPPORTED_KEY_TYPE} {base64.b64encode(blob).decode()} {comment}\n"


def make_detached(seed: bytes, message: bytes, namespace: str, hash_algorithm: str = "sha512") -> str:
    pub = ed25519_keypair(seed)[1]
    h = SUPPORTED_HASHES[hash_algorithm](message).digest()
    signed = (MAGIC + _string(namespace.encode()) + _string(b"")
              + _string(hash_algorithm.encode()) + _string(h))
    raw = ed25519_sign(seed, signed)
    blob = (MAGIC + struct.pack(">I", 1)
            + _string(_string(SUPPORTED_KEY_TYPE.encode()) + _string(pub))
            + _string(namespace.encode()) + _string(b"") + _string(hash_algorithm.encode())
            + _string(_string(SUPPORTED_KEY_TYPE.encode()) + _string(raw)))
    b64 = base64.b64encode(blob).decode()
    body = "\n".join(b64[i:i + 70] for i in range(0, len(b64), 70))
    return f"-----BEGIN SSH SIGNATURE-----\n{body}\n-----END SSH SIGNATURE-----\n"
