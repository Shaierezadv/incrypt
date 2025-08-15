import base64
import hashlib
import json
import random
from typing import List, Optional, Tuple

ZWSP = "\u200b"  # zero-width space
ZWNJ = "\u200c"  # zero-width non-joiner
SEP = "\u2063"   # invisible separator (sentinel)
START = SEP + ZWSP + ZWNJ + ZWSP
END = SEP + ZWNJ + ZWSP + ZWNJ


def compute_file_id(original_text: str) -> str:
    digest = hashlib.sha256(original_text.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest[:9]).decode("ascii").rstrip("=")


def _zw_encode(data: bytes) -> str:
    bits = ''.join(f"{byte:08b}" for byte in data)
    return ''.join(ZWSP if b == '0' else ZWNJ for b in bits)


def _zw_decode(s: str) -> bytes:
    bits = ''.join('0' if ch == ZWSP else '1' for ch in s)
    by = int(bits, 2).to_bytes(len(bits) // 8, 'big') if bits else b''
    return by


def encode_payload(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    b = base64.urlsafe_b64encode(raw)
    zw = _zw_encode(b)
    return START + zw + END


def try_decode_payload(text: str) -> Optional[dict]:
    # Search for START ... END sequences and decode the first one
    start_idx = text.find(START)
    if start_idx == -1:
        return None
    end_idx = text.find(END, start_idx + len(START))
    if end_idx == -1:
        return None
    zw = text[start_idx + len(START):end_idx]
    try:
        b = _zw_decode(zw)
        data = base64.urlsafe_b64decode(b)
        return json.loads(data)
    except Exception:
        return None


def embed_watermarks(text: str, key_id: str, file_id: str, repetitions: int = 3) -> str:
    payload = {"v": 1, "kid": key_id, "fid": file_id}
    zw_block = encode_payload(payload)
    # Visible light tags
    tag = f"[wm|v=1|kid={key_id}|fid={file_id}]"

    out = text
    if not out:
        return zw_block + tag
    positions = []
    step = max(1, len(out) // (repetitions + 1))
    for i in range(1, repetitions + 1):
        positions.append(i * step)
    offset = 0
    for i, pos in enumerate(positions):
        insert_at = min(len(out), pos + offset)
        block = (zw_block if i % 2 == 0 else tag)
        out = out[:insert_at] + block + out[insert_at:]
        offset += len(block)
    return out


def extract_visible_tags(text: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    cursor = 0
    while True:
        start = text.find("[wm|v=1|kid=", cursor)
        if start == -1:
            break
        end = text.find("]", start)
        if end == -1:
            break
        tag = text[start + 1:end]  # wm|v=1|kid=...|fid=...
        parts = tag.split("|")
        kid = ""
        fid = ""
        for p in parts:
            if p.startswith("kid="):
                kid = p[4:]
            elif p.startswith("fid="):
                fid = p[4:]
        if kid and fid:
            results.append((kid, fid))
        cursor = end + 1
    return results