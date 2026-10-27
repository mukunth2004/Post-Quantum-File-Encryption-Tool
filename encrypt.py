import os
import struct

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pqc.utils import derive_aes_key, load_binary


KEM_NAME = "ML-KEM-768"
IV_SIZE = 12


def encrypt_file(input_filepath: str, public_key_path: str) -> str:
    public_key = load_binary(public_key_path)

    kem = oqs.KeyEncapsulation(KEM_NAME)
    try:
        ciphertext_kem, shared_secret = kem.encap_secret(public_key)
    finally:
        kem.free()

    aes_key = derive_aes_key(shared_secret)
    iv = os.urandom(IV_SIZE)
    plaintext = load_binary(input_filepath)
    encrypted_content = AESGCM(aes_key).encrypt(iv, plaintext, None)

    output_filepath = input_filepath + ".pqc"
    kem_len = struct.pack(">I", len(ciphertext_kem))

    with open(output_filepath, "wb") as f:
        f.write(kem_len)
        f.write(ciphertext_kem)
        f.write(iv)
        f.write(encrypted_content)

    return output_filepath
