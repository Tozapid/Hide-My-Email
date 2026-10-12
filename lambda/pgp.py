"""OpenPGP signatures of the mail an alias sends, and the key to check them.

Every alias has an Ed25519 key of its own (OpenPGP version 4, EdDSA as GnuPG
writes it) with the alias address as its only user id, a self-signature for
certifying and signing, and no expiry. The function signs replies and new
messages with it (PGP/MIME, RFC 3156) and publishes it in the Web Key
Directory of the alias domain, where mail clients find it by the address.

The private key is never stored: the caller derives its 32-byte seed from a
secret and the alias (hide_my_email.alias_signing_key), and the key's creation
time, kept with the alias, fixes the fingerprint. Ed25519 comes from the
cryptography package, in a Lambda layer.
"""

import base64
import hashlib
import struct
import time

EDDSA = 22  # EdDSA, the version 4 form GnuPG uses for Ed25519
SHA256 = 8
ED25519_OID = bytes.fromhex("2b06010401da470f01")  # 1.3.6.1.4.1.11591.15.1
ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


# Armor ----------------------------------------------------------------------

def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor(data, kind):
    encoded = base64.b64encode(data).decode()
    lines = [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    checksum = base64.b64encode(crc24(data).to_bytes(3, "big")).decode()
    return "\r\n".join([f"-----BEGIN {kind}-----", "", *lines, "=" + checksum, f"-----END {kind}-----", ""])


# Packets --------------------------------------------------------------------

def packet(tag, body):
    length = len(body)
    if length < 192:
        header = bytes([length])
    elif length < 8384:
        length -= 192
        header = bytes([(length >> 8) + 192, length & 0xFF])
    else:
        header = b"\xff" + struct.pack(">I", length)
    return bytes([0xC0 | tag]) + header + body


def mpi(value):
    value = value.lstrip(b"\x00") or b"\x00"
    return struct.pack(">H", (len(value) - 1) * 8 + value[0].bit_length()) + value


def subpacket(kind, data):
    body = bytes([kind]) + data
    if len(body) < 192:
        return bytes([len(body)]) + body
    return b"\xff" + struct.pack(">I", len(body)) + body


# Web Key Directory ----------------------------------------------------------

def zbase32(data):
    bits = "".join(f"{byte:08b}" for byte in data)
    bits += "0" * (-len(bits) % 5)
    return "".join(ZBASE32[int(bits[i:i + 5], 2)] for i in range(0, len(bits), 5))


def wkd_hash(local):
    """The file name of a key in the Web Key Directory: the z-base-32 SHA-1 of
    the lower-case local part (draft-koch-openpgp-webkey-service)."""
    return zbase32(hashlib.sha1(local.lower().encode()).digest())


# Keys -----------------------------------------------------------------------

class SigningKey:
    def __init__(self, seed, created, user_id):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519

        self._private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        public = self._private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.created = int(created)
        self.user_id = user_id
        self.public_body = b"\x04" + struct.pack(">I", self.created) + bytes([EDDSA, len(ED25519_OID)]) + ED25519_OID + mpi(b"\x40" + public)
        self.fingerprint = hashlib.sha1(b"\x99" + struct.pack(">H", len(self.public_body)) + self.public_body).digest()
        self.key_id = self.fingerprint[-8:]

    # A version 4 signature: the hashed subpackets with the issuer, the left
    # two octets of the hash and r and s of the EdDSA signature of the hash.
    def signature(self, kind, prefix, created, hashed):
        hashed = subpacket(2, struct.pack(">I", created)) + hashed + subpacket(33, b"\x04" + self.fingerprint)
        head = bytes([4, kind, EDDSA, SHA256]) + struct.pack(">H", len(hashed)) + hashed
        digest = hashlib.sha256(prefix + head + b"\x04\xff" + struct.pack(">I", len(head))).digest()
        signed = self._private.sign(digest)
        unhashed = subpacket(16, self.key_id)
        return packet(2, head + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + mpi(signed[:32]) + mpi(signed[32:]))

    def public_key(self):
        """The key with its user id and self-signature, as WKD serves it."""
        user_id = self.user_id.encode()
        prefix = b"\x99" + struct.pack(">H", len(self.public_body)) + self.public_body + b"\xb4" + struct.pack(">I", len(user_id)) + user_id
        hashed = (
            subpacket(27, b"\x03")  # certify and sign
            + subpacket(11, bytes([9, 8, 7]))  # AES-256, AES-192, AES-128
            + subpacket(21, bytes([10, 9, 8]))  # SHA-512, SHA-384, SHA-256
            + subpacket(22, bytes([2, 1, 0]))  # ZLIB, ZIP, none
            + subpacket(30, b"\x01")  # modification detection
            + subpacket(25, b"\x01")  # the primary user id
        )
        return packet(6, self.public_body) + packet(13, user_id) + self.signature(0x13, prefix, self.created, hashed)

    def armored_public_key(self):
        return armor(self.public_key(), "PGP PUBLIC KEY BLOCK")

    def sign(self, data, now=None):
        """The armored detached signature of data, a binary document; the
        signer's user id tells clients where to look for the key."""
        created = int(time.time() if now is None else now)
        return armor(self.signature(0x00, data, created, subpacket(28, self.user_id.encode())), "PGP SIGNATURE")
