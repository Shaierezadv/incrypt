import base64
import os
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aesgcm_key() -> bytes:
    """Generate a 256-bit AES-GCM key."""
    return os.urandom(32)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def encrypt_aesgcm(key: bytes, plaintext: str, aad: Optional[bytes] = None) -> Tuple[str, str]:
    """Encrypt text with AES-GCM.

    Returns (nonce_b64, ciphertext_b64). The ciphertext includes the GCM tag appended.
    """
    if aad is None:
        aad = b""
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)
    return b64e(nonce), b64e(ciphertext)


def decrypt_aesgcm(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: Optional[bytes] = None) -> str:
    if aad is None:
        aad = b""
    nonce = b64d(nonce_b64)
    ciphertext = b64d(ciphertext_b64)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    return plaintext.decode("utf-8")