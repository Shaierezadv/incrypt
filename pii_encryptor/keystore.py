import json
import os
import time
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from .crypto_util import generate_aesgcm_key, b64e, b64d


KEYSTORE_DIR = Path(os.path.expanduser("~/.pii_encryptor"))
KEYSTORE_FILE = KEYSTORE_DIR / "keys.json"


@dataclass
class KeyRecord:
    key_id: str
    key_bytes: bytes
    label: str
    created_at_epoch: int


def _now_epoch() -> int:
    return int(time.time())


def _ensure_dir() -> None:
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)


def _load_keystore() -> Dict:
    _ensure_dir()
    if not KEYSTORE_FILE.exists():
        return {"version": 1, "keys": {}, "default_key_id": None}
    with KEYSTORE_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def _save_keystore(data: Dict) -> None:
    tmp = KEYSTORE_FILE.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, KEYSTORE_FILE)


def _generate_key_id(label: Optional[str] = None) -> str:
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    rnd = secrets.token_hex(4)
    if label:
        safe_label = "".join(ch for ch in label if ch.isalnum() or ch in ("-", "_"))[:20]
        return f"k1-{ts}-{safe_label}-{rnd}"
    return f"k1-{ts}-{rnd}"


def create_key(label: Optional[str] = None, set_default: bool = True) -> KeyRecord:
    data = _load_keystore()
    key_id = _generate_key_id(label)
    key_bytes = generate_aesgcm_key()
    record = {
        "key_b64": b64e(key_bytes),
        "label": label or "",
        "created_at": _now_epoch(),
    }
    data.setdefault("keys", {})[key_id] = record
    if set_default or not data.get("default_key_id"):
        data["default_key_id"] = key_id
    _save_keystore(data)
    return KeyRecord(key_id=key_id, key_bytes=key_bytes, label=record["label"], created_at_epoch=record["created_at"]) 


def list_keys() -> Dict[str, KeyRecord]:
    data = _load_keystore()
    result: Dict[str, KeyRecord] = {}
    for kid, rec in data.get("keys", {}).items():
        result[kid] = KeyRecord(
            key_id=kid,
            key_bytes=b64d(rec["key_b64"]),
            label=rec.get("label", ""),
            created_at_epoch=int(rec.get("created_at", 0)),
        )
    return result


def get_key(key_id: str) -> Optional[KeyRecord]:
    return list_keys().get(key_id)


def get_default_key_id() -> Optional[str]:
    data = _load_keystore()
    return data.get("default_key_id")


def set_default_key_id(key_id: str) -> None:
    data = _load_keystore()
    if key_id not in data.get("keys", {}):
        raise ValueError(f"Key not found: {key_id}")
    data["default_key_id"] = key_id
    _save_keystore(data)