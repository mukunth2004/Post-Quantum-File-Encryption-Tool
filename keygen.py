import os

import oqs


def generate_keypair(save_dir="."):
    os.makedirs(save_dir, exist_ok=True)

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    try:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    finally:
        kem.free()

    pub_path = os.path.join(save_dir, "alice.pub")
    key_path = os.path.join(save_dir, "alice.key")

    with open(pub_path, "wb") as f:
        f.write(public_key)
    with open(key_path, "wb") as f:
        f.write(secret_key)

    print(f"Public key saved: {pub_path}")
    print(f"Private key saved: {key_path}")
    print("Keep alice.key private and do not commit it to version control.")

    return pub_path, key_path


if __name__ == "__main__":
    generate_keypair()
