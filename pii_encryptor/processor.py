import re
from typing import Dict, List, Optional, Tuple

from .crypto_util import encrypt_aesgcm, decrypt_aesgcm
from .keystore import get_key, get_default_key_id
from .pii_patterns import find_all_pii, PIIMatch
from .watermark import compute_file_id, embed_watermarks, try_decode_payload, extract_visible_tags


TOKEN_RE = re.compile(r"\[pii\|v=1\|kid=([^|\]]+)\|t=([^|\]]+)\|i=(\d+)\|n=([^|\]]+)\|c=([^\]]+)\]")


def _make_token(kid: str, pii_kind: str, idx: int, nonce_b64: str, ct_b64: str) -> str:
    return f"[pii|v=1|kid={kid}|t={pii_kind}|i={idx}|n={nonce_b64}|c={ct_b64}]"


def _aad_for(pii_kind: str, idx: int, file_id: str) -> bytes:
    return f"pii|{pii_kind}|{idx}|{file_id}".encode("utf-8")


def encrypt_text(text: str, key_id: Optional[str] = None) -> Tuple[str, Dict]:
    if key_id is None:
        key_id = get_default_key_id()
        if not key_id:
            raise RuntimeError("No default key configured. Generate one with keygen.")
    key_rec = get_key(key_id)
    if not key_rec:
        raise RuntimeError(f"Key not found: {key_id}")

    file_id = compute_file_id(text)
    pii_matches = find_all_pii(text)

    # Replace from end to start to maintain indices
    out = text
    replaced: List[Tuple[PIIMatch, str]] = []
    for idx, match in enumerate(reversed(pii_matches)):
        seq = len(pii_matches) - 1 - idx
        aad = _aad_for(match.kind, seq, file_id)
        n_b64, c_b64 = encrypt_aesgcm(key_rec.key_bytes, match.value, aad)
        token = _make_token(key_id, match.kind, seq, n_b64, c_b64)
        out = out[:match.start] + token + out[match.end:]
        replaced.append((match, token))

    out = embed_watermarks(out, key_id, file_id, repetitions=3)

    metadata = {
        "key_id": key_id,
        "file_id": file_id,
        "num_pii": len(pii_matches),
    }
    return out, metadata


def decrypt_text(text: str) -> Tuple[str, Dict]:
    # Try to find watermark for kid/fid
    kid, fid = _guess_kid_fid(text)

    replacements = 0

    def _replace(match: re.Match) -> str:
        nonlocal replacements
        mkid = match.group(1)
        pii_kind = match.group(2)
        idx = int(match.group(3))
        n_b64 = match.group(4)
        c_b64 = match.group(5)
        rec_kid = mkid or kid
        if not rec_kid:
            return match.group(0)
        key_rec = get_key(rec_kid)
        if not key_rec:
            return match.group(0)
        aad = _aad_for(pii_kind, idx, fid or "")
        try:
            pt = decrypt_aesgcm(key_rec.key_bytes, n_b64, c_b64, aad)
            replacements += 1
            return pt
        except Exception:
            return match.group(0)

    out = TOKEN_RE.sub(_replace, text)

    meta = {"key_id": kid, "file_id": fid, "replaced": replacements}
    return out, meta


def inspect_text(text: str) -> Dict:
    kid, fid = _guess_kid_fid(text)
    tokens = TOKEN_RE.findall(text)
    return {
        "key_id": kid,
        "file_id": fid,
        "num_tokens": len(tokens),
        "token_key_ids": sorted(set(k for (k, *_rest) in tokens)),
    }


def _guess_kid_fid(text: str) -> Tuple[Optional[str], Optional[str]]:
    payload = try_decode_payload(text)
    if payload and isinstance(payload, dict):
        return payload.get("kid"), payload.get("fid")
    tags = extract_visible_tags(text)
    if tags:
        # return the most frequent pair
        from collections import Counter
        cnt = Counter(tags)
        (kid, fid), _ = cnt.most_common(1)[0]
        return kid, fid
    # Fallback: infer from first token
    m = TOKEN_RE.search(text)
    if m:
        return m.group(1), None
    return None, None