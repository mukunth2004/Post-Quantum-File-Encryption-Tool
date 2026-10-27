import argparse
import os

from pqc.benchmark import run_benchmark
from pqc.decrypt import decrypt_file
from pqc.encrypt import encrypt_file
from pqc.keygen import generate_keypair


def main():
    parser = argparse.ArgumentParser(
        description="PQC Tool - Post-Quantum File Encryption"
    )
    subparsers = parser.add_subparsers(dest="command")

    keygen_parser = subparsers.add_parser("keygen", help="Generate an ML-KEM-768 keypair")
    keygen_parser.add_argument(
        "--output", default=".", help="Directory to save keys (default: current directory)"
    )

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file using ML-KEM and AES-256-GCM"
    )
    encrypt_parser.add_argument("file", help="File to encrypt")
    encrypt_parser.add_argument(
        "--pubkey", default="alice.pub", help="Path to the public key (default: alice.pub)"
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a .pqc file using the private key"
    )
    decrypt_parser.add_argument("file", help="Encrypted .pqc file")
    decrypt_parser.add_argument(
        "--privkey", default="alice.key", help="Path to the private key (default: alice.key)"
    )

    benchmark_parser = subparsers.add_parser(
        "benchmark", help="Benchmark ML-KEM-768 against RSA-2048"
    )
    benchmark_parser.add_argument(
        "--iterations", type=int, default=100, help="Iterations per test (default: 100)"
    )

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if args.command == "keygen":
        generate_keypair(args.output)
        return

    if args.command == "encrypt":
        if not os.path.isfile(args.file):
            parser.error(f"file not found: {args.file}")
        if not os.path.isfile(args.pubkey):
            parser.error(f"public key not found: {args.pubkey}")
        output = encrypt_file(args.file, args.pubkey)
        print(f"Encrypted file: {output}")
        return

    if args.command == "decrypt":
        if not os.path.isfile(args.file):
            parser.error(f"file not found: {args.file}")
        if not os.path.isfile(args.privkey):
            parser.error(f"private key not found: {args.privkey}")
        output = decrypt_file(args.file, args.privkey)
        print(f"Decrypted file: {output}")
        return

    if args.iterations < 1:
        parser.error("iterations must be at least 1")
    run_benchmark(args.iterations)


if __name__ == "__main__":
    main()
