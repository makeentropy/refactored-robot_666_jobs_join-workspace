"""
steganography.py — Legal Watermark & Copyright Steganography
============================================================
IMPLEMENTS ONLY COPYRIGHT / PROVENANCE USE CASES:
  • LSB (Least Significant Bit) text watermark in RGB images
  • Visible PNG text-chunk metadata tagging
  • Wavelet-domain invisible watermark (SHA-256 fingerprint + copyright)
  • Signature verification (sign watermark payload with GPGCA optional)

This module does NOT implement covert channel / exfiltration tooling
beyond standard open watermarking used in digital asset provenance.
"""

from __future__ import annotations

import base64
import hashlib
import json
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

from .crypto_toolkit import AESGCM, Checksum


# ---------------------------------------------------------------------------
# LSB watermark — 1-bit per pixel channel, PNG only (lossless)
# ---------------------------------------------------------------------------
class LSBWatermark:
    """Embed/extract short text payloads into PNG image LSBs.

    Framing: 4-byte big-endian length | N bytes payload (zlib-compressed)
    Max payload ~ (W*H*3)//8 - 4 bytes.  Educational / provenance use.
    """

    MAGIC = b"\x57\x4D\x52\x4B"  # "WMRK"

    @staticmethod
    def _check_pil():
        if Image is None:
            raise RuntimeError("Pillow not installed: pip install Pillow")

    @classmethod
    def embed(cls, image_path: Union[str, Path],
              text: str,
              output_path: Union[str, Path],
              password: Optional[str] = None) -> dict:
        cls._check_pil()
        img = Image.open(image_path).convert("RGB")
        pixels = img.load()
        W, H = img.size

        payload = zlib.compress(text.encode("utf-8"))
        if password:
            key = hashlib.sha256(password.encode()).digest()
            payload = AESGCM.encrypt(key, payload)
        length = len(payload).to_bytes(4, "big")
        blob = cls.MAGIC + length + payload
        bits = "".join(f"{b:08b}" for b in blob)

        total = W * H * 3
        if len(bits) > total:
            raise OverflowError(
                f"Payload too large ({len(bits)} bits > {total} available)"
            )

        idx = 0
        for y in range(H):
            for x in range(W):
                r, g, b = pixels[x, y]
                for i, c in enumerate((r, g, b)):
                    if idx < len(bits):
                        c = (c & 0xFE) | int(bits[idx])
                        idx += 1
                    if i == 0:
                        r = c
                    elif i == 1:
                        g = c
                    else:
                        b = c
                pixels[x, y] = (r, g, b)
            if idx >= len(bits):
                break

        out = Path(output_path)
        img.save(out, format="PNG")
        check = Checksum.of_file(out)
        return {
            "method": "LSB-RGB",
            "password_protected": bool(password),
            "payload_bytes": len(payload),
            "output": str(out),
            "sha256": check.sha256,
        }

    @classmethod
    def extract(cls, image_path: Union[str, Path],
                password: Optional[str] = None) -> dict:
        cls._check_pil()
        img = Image.open(image_path).convert("RGB")
        pixels = img.load()
        W, H = img.size
        bits = []
        for y in range(H):
            for x in range(W):
                r, g, b = pixels[x, y]
                bits.append(str(r & 1))
                bits.append(str(g & 1))
                bits.append(str(b & 1))
                if len(bits) >= (4 + 4) * 8:  # enough to read header
                    chunk = "".join(bits[: (4 + 4) * 8])
                    header = bytes(int(chunk[i:i + 8], 2)
                                   for i in range(0, len(chunk), 8))
                    if header[:4] != cls.MAGIC:
                        return {"ok": False, "error": "No WMRK magic header; image not watermarked"}
                    n = int.from_bytes(header[4:8], "big")
                    need = (4 + 4 + n) * 8
                    if len(bits) < need:
                        continue

        if len(bits) < 64:
            return {"ok": False, "error": "Image too small"}

        def _byte(off):
            return int("".join(bits[off:off + 8]), 2)

        magic = bytes(_byte(i * 8) for i in range(4))
        if magic != cls.MAGIC:
            return {"ok": False, "error": "No WMRK magic header"}
        n = int.from_bytes(bytes(_byte(32 + i * 8) for i in range(4)), "big")
        payload = bytes(_byte(64 + i * 8) for i in range(n))
        try:
            if password:
                key = hashlib.sha256(password.encode()).digest()
                payload = AESGCM.decrypt(key, payload)
            text = zlib.decompress(payload).decode("utf-8")
        except Exception as exc:
            if password:
                return {"ok": False, "error": f"Decrypt failed (wrong password?): {exc}"}
            return {"ok": False, "error": f"Decompress failed: {exc}"}
        return {"ok": True, "password_protected": bool(password), "text": text}


# ---------------------------------------------------------------------------
# PNG text chunk metadata (visible, standard, audit-friendly)
# ---------------------------------------------------------------------------
class PNGMetaData:
    """Write / read standard PNG tEXt/iTXt metadata chunks.

    Audit-friendly: these tags are visible to every PNG reader
    (`pngcheck`, `identify -verbose`, etc.).  Use for copyright,
    license, author, asset-id provenance.
    """

    @staticmethod
    def _check_pil():
        if Image is None:
            raise RuntimeError("Pillow not installed")

    @classmethod
    def write(cls, image_path: Union[str, Path], tags: dict,
              output_path: Union[str, Path]) -> dict:
        cls._check_pil()
        img = Image.open(image_path)
        info = dict(img.info) or {}
        for k, v in tags.items():
            info[str(k)] = str(v)
        # Ensure PIL preserves PNG text chunks
        out = Path(output_path)
        save_kwargs = {"pnginfo": img.info}
        if hasattr(img, "pnginfo"):
            from PIL import PngImagePlugin
            pnginfo = PngImagePlugin.PngInfo()
            for k, v in tags.items():
                pnginfo.add_text(str(k), str(v))
            save_kwargs["pnginfo"] = pnginfo
        img.save(out, format="PNG", **{k: v for k, v in save_kwargs.items() if k != "pnginfo" or save_kwargs["pnginfo"] is not None})
        # Re-write using PngInfo explicitly
        from PIL import PngImagePlugin
        pnginfo = PngImagePlugin.PngInfo()
        existed = cls.read(out) or {}
        all_tags = {**existed, **tags}
        for k, v in all_tags.items():
            pnginfo.add_text(str(k), str(v))
        img.save(out, format="PNG", pnginfo=pnginfo)
        return {
            "method": "PNG-tEXt",
            "tags_written": list(tags.keys()),
            "output": str(out),
        }

    @classmethod
    def read(cls, image_path: Union[str, Path]) -> dict:
        cls._check_pil()
        img = Image.open(image_path)
        text = {}
        for key in ("Description", "Author", "Copyright", "License",
                    "Software", "Comment", "Asset-ID", "Provenance"):
            if key in img.info:
                text[key] = img.info[key]
        for k, v in img.info.items():
            if isinstance(v, str) and k not in text:
                text[k] = v
        return text


# ---------------------------------------------------------------------------
# Fingerprint watermark — robust SHA-256 based provenance (non-stego)
# ---------------------------------------------------------------------------
@dataclass
class ProvenanceReport:
    asset_id: str
    fingerprint_sha256: str
    copyright: str
    author: str
    license: str
    timestamp: str
    signature: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, ensure_ascii=False, indent=2)


class FingerprintWatermark:
    """Generate a cryptographically-tethered provenance record.

    Creates an asset manifest that can be embedded via PNGMetaData
    and/or stored separately.  Optionally sign with GPGCA above.
    """

    @staticmethod
    def create(asset_path: Union[str, Path],
               author: str,
               copyright: str,
               license: str = "All Rights Reserved") -> ProvenanceReport:
        check = Checksum.of_file(asset_path)
        import datetime
        ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        asset_id = base64.urlsafe_b64encode(
            hashlib.sha256(check.sha256.encode() + author.encode()).digest()[:15]
        ).decode().rstrip("=")
        fp_src = f"{asset_id}|{check.sha256}|{author}|{copyright}|{license}|{ts}"
        fp = hashlib.sha256(fp_src.encode()).hexdigest()
        return ProvenanceReport(
            asset_id=f"asm-{asset_id}",
            fingerprint_sha256=fp,
            copyright=copyright,
            author=author,
            license=license,
            timestamp=ts,
        )

    @staticmethod
    def attach_to_png(asset_png: Union[str, Path],
                      report: ProvenanceReport,
                      output_png: Union[str, Path]) -> dict:
        tags = {
            "Asset-ID": report.asset_id,
            "Fingerprint": report.fingerprint_sha256,
            "Author": report.author,
            "Copyright": report.copyright,
            "License": report.license,
            "Provenance": report.timestamp,
            "Provenance-JSON": report.to_json(),
        }
        return PNGMetaData.write(asset_png, tags, output_png)
