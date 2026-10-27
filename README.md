# PQC Tool

A Python CLI for **post-quantum file encryption** using **ML-KEM-768** and **AES-256-GCM**.

The project uses a hybrid encryption approach: ML-KEM is used to establish a shared secret, which is then converted into an AES-256 key using HKDF. AES-GCM is used to encrypt the actual file.

## How it works

```text
ML-KEM-768
    ↓
Shared Secret
    ↓
HKDF
    ↓
AES-256 Key
    ↓
AES-256-GCM
    ↓
Encrypted File (.pqc)
```

### Why hybrid encryption?

ML-KEM is a **Key Encapsulation Mechanism (KEM)**, so it is used to establish a shared secret rather than encrypting large files directly.

AES-256-GCM is then used for the actual file encryption because symmetric encryption is much more efficient for bulk data.

## Features

- ML-KEM-768 for post-quantum key establishment
- AES-256-GCM for file encryption and integrity
- HKDF for deriving the AES-256 key
- Simple command-line interface
- Benchmark comparing ML-KEM-768 with RSA-2048

## Usage

### Generate keys

```bash
python main.py keygen
```

This generates:

```text
alice.pub
alice.key
```

### Encrypt

```bash
python main.py encrypt <input_file> <public_key> <output_file>
```

### Decrypt

```bash
python main.py decrypt <encrypted_file> <private_key> <output_file>
```

### Benchmark

```bash
python main.py benchmark --iterations 100
```

The benchmark compares ML-KEM-768 and RSA-2048 for key generation, encapsulation/encryption, and decapsulation/decryption.

## Project Structure

```text
.
├── main.py
├── pqc/
│   ├── keygen.py
│   ├── encrypt.py
│   ├── decrypt.py
│   ├── benchmark.py
│   └── utils.py
└── README.md
```

## Technologies

- Python
- ML-KEM-768 - `liboqs-python`
- AES-256-GCM - `cryptography`
- HKDF — `cryptography`
- RSA-2048 — benchmarking

## Security Notes

The project uses fresh random IVs for AES-GCM and derives the encryption key from the ML-KEM shared secret using HKDF.

Some limitations of the current implementation:

- Private keys are stored without password protection.
- Files are loaded into memory rather than processed as a stream.
- The file format does not currently include versioning or algorithm identifiers.
- The project has not been independently security audited.

## Reference

ML-KEM is standardised by NIST in **FIPS 203**.

