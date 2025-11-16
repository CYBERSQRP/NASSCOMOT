"""
Module 1: Quantum-Safe Cryptography Layer

This module provides post-quantum cryptographic primitives for automotive systems.
It implements NIST-standardized PQC algorithms: ML-KEM, ML-DSA, and SLH-DSA.

Components:
- ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) - formerly Kyber
- ML-DSA (Module-Lattice-Based Digital Signature Algorithm) - formerly Dilithium
- SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) - formerly SPHINCS+
- Hybrid TLS 1.3 with PQC key exchange
- Cryptographic utilities and helpers

Compliance: ISO/SAE 21434, NIST FIPS 203/204/205
"""

__version__ = "1.0.0"
__author__ = "LTTS Quantum Security Team"

from .mlkem import (
    MLKEMKeyExchange,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
)

from .mldsa import (
    MLDSASignature,
    MLDSA44,
    MLDSA65,
    MLDSA87,
)

from .slhdsa import (
    SLHDSASignature,
    SLHDSA128s,
    SLHDSA192s,
    SLHDSA256s,
)

from .hybrid_tls import (
    HybridTLSContext,
    PQCTLSHandshake,
)

from .utils import (
    PQCKeyPair,
    SecurityLevel,
    hash_function,
    constant_time_compare,
)

from .secure_memory import (
    SecureBytes,
    SecureKeyPair,
    secure_compare,
    secure_random_bytes,
    secure_operation,
    zeroize_bytes,
    create_secure_keypair,
)

__all__ = [
    # ML-KEM (Key Encapsulation)
    "MLKEMKeyExchange",
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",

    # ML-DSA (Digital Signatures)
    "MLDSASignature",
    "MLDSA44",
    "MLDSA65",
    "MLDSA87",

    # SLH-DSA (Stateless Hash Signatures)
    "SLHDSASignature",
    "SLHDSA128s",
    "SLHDSA192s",
    "SLHDSA256s",

    # Hybrid TLS
    "HybridTLSContext",
    "PQCTLSHandshake",

    # Utilities
    "PQCKeyPair",
    "SecurityLevel",
    "hash_function",
    "constant_time_compare",

    # Secure Memory
    "SecureBytes",
    "SecureKeyPair",
    "secure_compare",
    "secure_random_bytes",
    "secure_operation",
    "zeroize_bytes",
    "create_secure_keypair",
]
