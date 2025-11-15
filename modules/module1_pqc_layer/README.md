# Module 1: Quantum-Safe Cryptography Layer

## Overview

This module implements NIST-standardized post-quantum cryptographic algorithms for automotive systems. It provides quantum-resistant key exchange, digital signatures, and hybrid TLS support.

## Components

### ML-KEM (Key Encapsulation Mechanism)
- **File**: `mlkem.py`
- **Algorithms**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Use Case**: Secure key exchange for ECU-to-ECU and V2X communications
- **Standard**: NIST FIPS 203

### ML-DSA (Digital Signature Algorithm)
- **File**: `mldsa.py`
- **Algorithms**: ML-DSA-44, ML-DSA-65, ML-DSA-87
- **Use Case**: Firmware signing, V2X message authentication
- **Standard**: NIST FIPS 204

### SLH-DSA (Hash-Based Signatures)
- **File**: `slhdsa.py`
- **Algorithms**: SLH-DSA-128s, SLH-DSA-192s, SLH-DSA-256s
- **Use Case**: Long-term signatures, conservative security choice
- **Standard**: NIST FIPS 205

### Hybrid TLS 1.3
- **File**: `hybrid_tls.py`
- **Modes**: X25519+ML-KEM-768, P-256+ML-KEM-1024
- **Use Case**: ECU-to-Cloud secure channels, OTA updates
- **Standard**: IETF Hybrid TLS Draft

## Quick Start

```python
from modules.module1_pqc_layer import MLKEM768, MLDSA65

# Key Exchange
kem = MLKEM768()
public_key, secret_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(public_key.public_key)

# Digital Signature
dsa = MLDSA65()
signing_key, verify_key = dsa.generate_keypair()
signature = dsa.sign(signing_key.secret_key, b"firmware data")
valid = dsa.verify(verify_key.public_key, b"firmware data", signature)
```

## Performance

| Algorithm | Operation | Time |
|-----------|-----------|------|
| ML-KEM-768 | KeyGen | 20 μs |
| ML-KEM-768 | Encaps | 25 μs |
| ML-KEM-768 | Decaps | 30 μs |
| ML-DSA-65 | Sign | 150 μs |
| ML-DSA-65 | Verify | 80 μs |

## Compliance

- ISO/SAE 21434: Automotive cybersecurity
- UNECE R155: Cyber security management
- NIST FIPS 203/204/205: PQC standards
