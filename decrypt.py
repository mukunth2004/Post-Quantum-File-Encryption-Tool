import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc.encrypt import IV_SIZE, KEM_NAME
from pqc.utils import derive_aes_key, load_binary


def decrypt_file(pqc_filepath: str, private_key_path: str) -> str:
    raw = load_binary(pqc_filepath)

    if len(raw) < 4:
        raise ValueError("Invalid .pqc file")

    kem_len = struct.unpack(">I", raw[:4])[0]
    cursor = 4

    if kem_len == 0 or len(raw) < cursor + kem_len + IV_SIZE + 16:
        raise ValueError("Invalid .pqc file")

    ciphertext_kem = raw[cursor:cursor + kem_len]
    cursor += kem_len
    iv = raw[cursor:cursor + IV_SIZE]
    cursor += IV_SIZE
    encrypted_content = raw[cursor:]

    private_key = load_binary(private_key_path)
    kem = oqs.KeyEncapsulation(KEM_NAME, private_key)
    try:
        shared_secret = kem.decap_secret(ciphertext_kem)
    finally:
        kem.free()

    aes_key = derive_aes_key(shared_secret)
    plaintext = AESGCM(aes_key).decrypt(iv, encrypted_content, None)

    output_filepath = pqc_filepath[:-4] + ".decrypted"
    with open(output_filepath, "wb") as f:
        f.write(plaintext)

    return output_filepath
