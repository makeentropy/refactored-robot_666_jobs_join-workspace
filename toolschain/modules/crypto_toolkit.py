"""
crypto_toolkit.py — Encryption, Hashing & Certificate Toolkit
=============================================================
Legal-compliant implementations of:
  • BaseXOR  — symmetric XOR-based cipher (base-key expansion)
  • Checksum — MD5, SHA-1/256/512, CRC32, Adler-32 data integrity
  • GPG-CA   — OpenPGP keypair gen / sign / verify / encrypt / decrypt
               via python-gnupg + optional local mini-CA workflow

All algorithms are standard open specifications. No "backdoor" or
obfuscated proprietary logic.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional, Union

try:
    import gnupg  # python-gnupg
except ImportError:  # pragma: no cover
    gnupg = None

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ---------------------------------------------------------------------------
# BaseXOR cipher — symmetric, keystream-expanded XOR
# ---------------------------------------------------------------------------
class BaseXOR:
    """Lightweight XOR cipher with deterministic key-expansion.

    NOT for high-security transport — intended for local obfuscation,
    teaching, and XOR-prober differential analysis ("prober").
    """

    def __init__(self, key: Union[str, bytes]):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if not key:
            raise ValueError("BaseXOR key must not be empty")
        self._key = key

    # -- internal helpers ---------------------------------------------------
    def _expand_key(self, length: int) -> bytes:
        """Expand the base key to `length` bytes using SHA-256 chaining."""
        out = bytearray()
        seed = self._key
        while len(out) < length:
            seed = hashlib.sha256(seed + self._key).digest()
            out.extend(seed)
        return bytes(out[:length])

    # -- public API ---------------------------------------------------------
    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        ks = self._expand_key(len(plaintext))
        return bytes(a ^ b for a, b in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.encrypt(ciphertext)  # XOR is self-inverse

    def encrypt_b64(self, plaintext: Union[str, bytes]) -> str:
        return base64.b64encode(self.encrypt(plaintext)).decode("ascii")

    def decrypt_b64(self, ciphertext_b64: str) -> bytes:
        return self.decrypt(base64.b64decode(ciphertext_b64))

    @staticmethod
    def prober(data: bytes, hint_text: str = "The quick brown") -> dict:
        """Brute-force XOR prober — looks for known plaintext hint.

        Returns candidate single-byte keys whose decrypted output
        contains `hint_text` (case-insensitive).  Educational/demo use.
        """
        hits = []
        lower_hint = hint_text.lower()
        for k in range(256):
            dec = bytes(b ^ k for b in data)
            try:
                s = dec.decode("utf-8", errors="ignore").lower()
                if lower_hint in s:
                    hits.append({"key": k, "preview": dec[:120]})
            except Exception:
                continue
        return {"total_keys_tested": 256, "matches": hits}


# ---------------------------------------------------------------------------
# Checksum / integrity
# ---------------------------------------------------------------------------
@dataclass
class ChecksumReport:
    file: str
    size: int
    md5: str
    sha1: str
    sha256: str
    sha512: str
    crc32: str
    adler32: str
    blake2b: str

    def as_table(self) -> str:
        rows = [
            ("File", self.file),
            ("Size (bytes)", str(self.size)),
            ("MD5", self.md5),
            ("SHA-1", self.sha1),
            ("SHA-256", self.sha256),
            ("SHA-512", self.sha512),
            ("CRC32", self.crc32),
            ("Adler-32", self.adler32),
            ("BLAKE2b", self.blake2b),
        ]
        w = max(len(r[0]) for r in rows)
        return "\n".join(f"  {k:<{w}}  {v}" for k, v in rows)


class Checksum:
    CHUNK = 1 << 20  # 1 MB

    @classmethod
    def of_file(cls, path: Union[str, Path]) -> ChecksumReport:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(path)
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        sha512 = hashlib.sha512()
        blake = hashlib.blake2b()
        crc = 0
        adler = zlib.adler32(b"") & 0xFFFFFFFF
        size = 0
        with p.open("rb") as fh:
            while True:
                buf = fh.read(cls.CHUNK)
                if not buf:
                    break
                size += len(buf)
                for h in (md5, sha1, sha256, sha512, blake):
                    h.update(buf)
                crc = zlib.crc32(buf, crc)
                adler = zlib.adler32(buf, adler) & 0xFFFFFFFF
        return ChecksumReport(
            file=str(p),
            size=size,
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
            sha256=sha256.hexdigest(),
            sha512=sha512.hexdigest(),
            crc32=f"{crc & 0xFFFFFFFF:08x}",
            adler32=f"{adler:08x}",
            blake2b=blake.hexdigest(),
        )

    @classmethod
    def of_data(cls, data: Union[str, bytes], label: str = "<data>") -> ChecksumReport:
        if isinstance(data, str):
            data = data.encode("utf-8")
        crc = zlib.crc32(data) & 0xFFFFFFFF
        adler = zlib.adler32(data) & 0xFFFFFFFF
        return ChecksumReport(
            file=label,
            size=len(data),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            sha256=hashlib.sha256(data).hexdigest(),
            sha512=hashlib.sha512(data).hexdigest(),
            crc32=f"{crc:08x}",
            adler32=f"{adler:08x}",
            blake2b=hashlib.blake2b(data).hexdigest(),
        )

    @staticmethod
    def verify_file(path: Union[str, Path], expected_sha256: str) -> bool:
        return Checksum.of_file(path).sha256 == expected_sha256.lower()


# ---------------------------------------------------------------------------
# GPG / CA — OpenPGP keyring (via `gpg` binary when available)
# ---------------------------------------------------------------------------
class GPGCA:
    """Mini local-CA wrapper around python-gnupg.

    Requires an installed `gpg` binary on the host PATH.
    Falls back to a pure-python RSA self-cert demo when gpg missing.
    """

    def __init__(self, home: Optional[Union[str, Path]] = None):
        self.home = Path(home) if home else Path.home() / ".gnupg-toolschain"
        self.home.mkdir(parents=True, exist_ok=True)
        self._gpg = gnupg.GPG(gnupghome=str(self.home)) if gnupg else None

    @property
    def available(self) -> bool:
        return self._gpg is not None

    # -- keypair ------------------------------------------------------------
    def generate_key(
        self,
        name_email: str,
        name_real: str = "Toolschain User",
        key_type: str = "RSA",
        key_length: int = 2048,
        passphrase: Optional[str] = None,
    ) -> dict:
        if not self._gpg:
            return self._fallback_generate(name_email, name_real, key_length)
        input_data = self._gpg.gen_key_input(
            name_real=name_real,
            name_email=name_email,
            key_type=key_type,
            key_length=key_length,
            passphrase=passphrase,
        )
        key = self._gpg.gen_key(input_data)
        return {
            "backend": "gnupg",
            "fingerprint": key.fingerprint,
            "keyid": getattr(key, "keyid", None),
            "home": str(self.home),
        }

    def list_keys(self, secret: bool = False) -> list:
        if not self._gpg:
            return []
        return self._gpg.list_keys(secret)

    # -- encrypt / decrypt --------------------------------------------------
    def encrypt(self, data: Union[str, bytes], recipients: Iterable[str]) -> str:
        if not self._gpg:
            raise RuntimeError("gpg binary not installed; encrypt unavailable")
        if isinstance(data, str):
            data = data.encode("utf-8")
        result = self._gpg.encrypt(data, list(recipients), armor=True)
        if not result.ok:
            raise ValueError(f"GPG encrypt failed: {result.status}")
        return str(result)

    def decrypt(self, armored: str, passphrase: Optional[str] = None) -> bytes:
        if not self._gpg:
            raise RuntimeError("gpg binary not installed; decrypt unavailable")
        result = self._gpg.decrypt(armored, passphrase=passphrase)
        if not result.ok:
            raise ValueError(f"GPG decrypt failed: {result.status}")
        return result.data

    # -- sign / verify ------------------------------------------------------
    def sign(self, data: Union[str, bytes], passphrase: Optional[str] = None,
             keyid: Optional[str] = None) -> str:
        if not self._gpg:
            raise RuntimeError("gpg binary not installed; sign unavailable")
        if isinstance(data, str):
            data = data.encode("utf-8")
        result = self._gpg.sign(data, passphrase=passphrase, keyid=keyid, armor=True)
        if not result:
            raise ValueError("GPG sign failed")
        return str(result)

    def verify(self, data: Union[str, bytes], signature: Optional[str] = None) -> dict:
        if not self._gpg:
            return {"backend": "gnupg-missing", "valid": False, "error": "gpg not installed"}
        if isinstance(data, str):
            data = data.encode("utf-8")
        v = self._gpg.verify(data) if signature is None else self._gpg.verify(signature, data)
        return {
            "valid": v.valid,
            "fingerprint": getattr(v, "fingerprint", None),
            "status": getattr(v, "status", None),
            "key_id": getattr(v, "key_id", None),
            "username": getattr(v, "username", None),
        }

    # -- fallback pure-Python RSA (educational) -----------------------------
    def _fallback_generate(self, email, real, bits) -> dict:
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
        pub_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        priv_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        outdir = self.home / "fallback-keys"
        outdir.mkdir(exist_ok=True)
        fp = hashlib.sha256((email + real).encode()).hexdigest()
        (outdir / f"{fp}.pub.pem").write_text(pub_pem)
        (outdir / f"{fp}.priv.pem").write_text(priv_pem)
        return {
            "backend": "cryptography-fallback",
            "fingerprint": fp,
            "key_pem_dir": str(outdir),
            "note": "Fallback RSA-PKCS1 demo, NOT OpenPGP compatible",
        }


# ---------------------------------------------------------------------------
# Advanced: AES-GCM wrapper (for GPGCA users wanting symmetric-only mode)
# ---------------------------------------------------------------------------
class AESGCM:
    """Standard AES-256-GCM for symmetric authenticated encryption."""

    KEY_LEN = 32
    NONCE_LEN = 12

    @classmethod
    def new_key(cls) -> bytes:
        return os.urandom(cls.KEY_LEN)

    @classmethod
    def encrypt(cls, key: bytes, plaintext: Union[str, bytes],
                aad: bytes = b"") -> bytes:
        if len(key) != cls.KEY_LEN:
            raise ValueError("AES-256-GCM requires 32-byte key")
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        nonce = os.urandom(cls.NONCE_LEN)
        c = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        e = c.encryptor()
        e.authenticate_additional_data(aad)
        ct = e.update(plaintext) + e.finalize()
        return nonce + e.tag + ct

    @classmethod
    def decrypt(cls, key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
        if len(key) != cls.KEY_LEN:
            raise ValueError("AES-256-GCM requires 32-byte key")
        if len(blob) < cls.NONCE_LEN + 16:
            raise ValueError("Malformed ciphertext blob")
        nonce, tag, ct = blob[:cls.NONCE_LEN], blob[cls.NONCE_LEN:cls.NONCE_LEN + 16], blob[cls.NONCE_LEN + 16:]
        c = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        d = c.decryptor()
        d.authenticate_additional_data(aad)
        return d.update(ct) + d.finalize()
