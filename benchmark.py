import time

import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


KEM_NAME = "ML-KEM-768"


def run_benchmark(iterations: int = 100):
    print(f"\nPQC vs RSA Benchmark ({iterations} iterations)")
    print("=" * 52)

    start = time.perf_counter()
    for _ in range(iterations):
        kem = oqs.KeyEncapsulation(KEM_NAME)
        kem.generate_keypair()
        kem.free()
    mlkem_keygen = (time.perf_counter() - start) / iterations * 1000

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_keygen = (time.perf_counter() - start) / iterations * 1000

    kem = oqs.KeyEncapsulation(KEM_NAME)
    mlkem_pub = kem.generate_keypair()
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_key.public_key()
    test_data = b"A" * 32

    start = time.perf_counter()
    for _ in range(iterations):
        mlkem_ct, _ = kem.encap_secret(mlkem_pub)
    mlkem_encap = (time.perf_counter() - start) / iterations * 1000

    oaep = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )
    start = time.perf_counter()
    for _ in range(iterations):
        rsa_ct = rsa_pub.encrypt(test_data, oaep)
    rsa_enc = (time.perf_counter() - start) / iterations * 1000

    mlkem_priv = kem.export_secret_key()
    kem_dec = oqs.KeyEncapsulation(KEM_NAME, mlkem_priv)

    start = time.perf_counter()
    for _ in range(iterations):
        kem_dec.decap_secret(mlkem_ct)
    mlkem_decap = (time.perf_counter() - start) / iterations * 1000

    start = time.perf_counter()
    for _ in range(iterations):
        rsa_key.decrypt(rsa_ct, oaep)
    rsa_dec = (time.perf_counter() - start) / iterations * 1000

    mlkem_pub_size = len(mlkem_pub)
    mlkem_priv_size = len(mlkem_priv)
    mlkem_ct_size = len(mlkem_ct)
    rsa_pub_bytes = rsa_pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    rsa_priv_bytes = rsa_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    rsa_ct_size = len(rsa_ct)

    kem.free()
    kem_dec.free()

    print(f"\n{'Operation':<28}{'ML-KEM-768':>12}{'RSA-2048':>12}")
    print("-" * 52)
    print(f"{'Key generation (ms)':<28}{mlkem_keygen:>12.3f}{rsa_keygen:>12.3f}")
    print(f"{'Encapsulation/encryption (ms)':<28}{mlkem_encap:>12.3f}{rsa_enc:>12.3f}")
    print(f"{'Decapsulation/decryption (ms)':<28}{mlkem_decap:>12.3f}{rsa_dec:>12.3f}")
    print(f"{'Public key size (bytes)':<28}{mlkem_pub_size:>12}{len(rsa_pub_bytes):>12}")
    print(f"{'Private key size (bytes)':<28}{mlkem_priv_size:>12}{len(rsa_priv_bytes):>12}")
    print(f"{'Ciphertext size (bytes)':<28}{mlkem_ct_size:>12}{rsa_ct_size:>12}")


if __name__ == "__main__":
    run_benchmark()
