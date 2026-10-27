import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_aes_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"pqc-tool-aes-key",
    )
    return hkdf.derive(shared_secret)


def save_binary(filepath: str, data: bytes) -> None:
    with open(filepath, "wb") as f:
        f.write(data)


def load_binary(filepath: str) -> bytes:
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, "rb") as f:
        return f.read()
