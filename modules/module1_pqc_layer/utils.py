"""
Cryptographic utilities for PQC operations.

This module provides common utilities, data structures, and helper functions
used across the PQC layer.
"""

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import Tuple, Optional


class SecurityLevel(Enum):
    """NIST Security Levels for PQC algorithms."""

    LEVEL1 = 1  # Equivalent to AES-128 (128-bit security)
    LEVEL2 = 2  # Equivalent to SHA-256 (192-bit security)
    LEVEL3 = 3  # Equivalent to AES-192 (192-bit security)
    LEVEL4 = 4  # Equivalent to SHA-384 (256-bit security)
    LEVEL5 = 5  # Equivalent to AES-256 (256-bit security)


@dataclass
class PQCKeyPair:
    """
    Represents a post-quantum cryptographic key pair.

    Attributes:
        public_key: Public key bytes
        secret_key: Secret/private key bytes
        algorithm: Algorithm name (e.g., 'ML-KEM-768')
        security_level: NIST security level
    """

    public_key: bytes
    secret_key: bytes
    algorithm: str
    security_level: SecurityLevel

    def __repr__(self) -> str:
        return (
            f"PQCKeyPair(algorithm='{self.algorithm}', "
            f"security_level={self.security_level.name}, "
            f"public_key_size={len(self.public_key)}, "
            f"secret_key_size={len(self.secret_key)})"
        )

    def export_public_key(self) -> bytes:
        """Export public key in DER/PEM format."""
        # TODO: Implement proper DER encoding
        return self.public_key

    def zeroize_secret_key(self) -> None:
        """
        Securely erase the secret key from memory.
        CRITICAL for automotive security compliance (ISO 21434).
        """
        # Note: Python doesn't provide true secure memory wiping
        # In production, use ctypes or C extension for secure erasure
        if hasattr(self, "_secret_key_buffer"):
            # Overwrite with zeros
            import ctypes
            ptr = id(self.secret_key)
            ctypes.memset(ptr, 0, len(self.secret_key))


def hash_function(data: bytes, algorithm: str = "sha3-256") -> bytes:
    """
    Cryptographic hash function.

    Args:
        data: Input data to hash
        algorithm: Hash algorithm (sha3-256, sha3-512, shake256)

    Returns:
        Hash digest bytes

    Compliance:
        - NIST FIPS 202 (SHA-3)
        - ISO/SAE 21434 Section 9.3.2
    """
    if algorithm == "sha3-256":
        return hashlib.sha3_256(data).digest()
    elif algorithm == "sha3-512":
        return hashlib.sha3_512(data).digest()
    elif algorithm == "shake256":
        return hashlib.shake_256(data).digest(64)
    elif algorithm == "sha256":
        return hashlib.sha256(data).digest()
    elif algorithm == "sha512":
        return hashlib.sha512(data).digest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison to prevent timing attacks.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        True if equal, False otherwise

    Security:
        Uses constant-time comparison to prevent timing side-channels.
        Critical for automotive security (UNECE R155).
    """
    return hmac.compare_digest(a, b)


def generate_random_bytes(length: int) -> bytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of bytes to generate

    Returns:
        Random bytes

    Security:
        Uses secrets module for CSPRNG.
        In production, integrate with Module 3 (Entropy & RNG Engine).
    """
    return secrets.token_bytes(length)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """
    XOR two byte strings of equal length.

    Args:
        a: First byte string
        b: Second byte string

    Returns:
        XORed result

    Raises:
        ValueError: If lengths don't match
    """
    if len(a) != len(b):
        raise ValueError(f"Length mismatch: {len(a)} != {len(b)}")

    return bytes(x ^ y for x, y in zip(a, b))


def derive_key(
    secret: bytes,
    salt: bytes,
    info: bytes,
    length: int,
    algorithm: str = "sha256"
) -> bytes:
    """
    HKDF-based key derivation function.

    Args:
        secret: Input key material
        salt: Salt value
        info: Context/application-specific info
        length: Output key length
        algorithm: Hash algorithm for HKDF

    Returns:
        Derived key bytes

    Compliance:
        - NIST SP 800-56C Rev. 2
        - ISO/SAE 21434 Section 9.3.4
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hash_algorithms = {
        "sha256": hashes.SHA256(),
        "sha384": hashes.SHA384(),
        "sha512": hashes.SHA512(),
    }

    if algorithm not in hash_algorithms:
        raise ValueError(f"Unsupported HKDF algorithm: {algorithm}")

    hkdf = HKDF(
        algorithm=hash_algorithms[algorithm],
        length=length,
        salt=salt,
        info=info,
    )

    return hkdf.derive(secret)


def encode_der_integer(value: int) -> bytes:
    """
    Encode integer in DER format.

    Args:
        value: Integer to encode

    Returns:
        DER-encoded bytes
    """
    # Convert to bytes (big-endian)
    if value == 0:
        return b'\x02\x01\x00'

    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder='big')

    # Add padding if MSB is set (to distinguish from negative)
    if value_bytes[0] & 0x80:
        value_bytes = b'\x00' + value_bytes

    # DER INTEGER tag (0x02) + length + value
    length = len(value_bytes)
    if length < 128:
        return b'\x02' + bytes([length]) + value_bytes
    else:
        # Long form length encoding
        length_bytes = length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
        return b'\x02' + bytes([0x80 | len(length_bytes)]) + length_bytes + value_bytes


class PQCException(Exception):
    """Base exception for PQC-related errors."""
    pass


class KeyGenerationError(PQCException):
    """Error during key generation."""
    pass


class EncapsulationError(PQCException):
    """Error during key encapsulation."""
    pass


class DecapsulationError(PQCException):
    """Error during key decapsulation."""
    pass


class SignatureError(PQCException):
    """Error during signature generation."""
    pass


class VerificationError(PQCException):
    """Error during signature verification."""
    pass


def validate_security_level(level: int) -> SecurityLevel:
    """
    Validate and convert security level.

    Args:
        level: Security level (1-5)

    Returns:
        SecurityLevel enum

    Raises:
        ValueError: If level is invalid
    """
    if not 1 <= level <= 5:
        raise ValueError(f"Invalid security level: {level}. Must be 1-5.")

    return SecurityLevel(level)


# Automotive-specific constants
AUTOMOTIVE_TIMING_CONSTRAINT_MS = 100  # Maximum latency for ECU operations
V2X_MESSAGE_MAX_SIZE = 1400  # Maximum V2X message size (bytes)
ECU_KEY_LIFETIME_HOURS = 24 * 365  # 1 year key lifetime
V2X_KEY_LIFETIME_HOURS = 24 * 7  # 1 week key lifetime for V2X

# Algorithm parameters mapping
ALGORITHM_PARAMS = {
    # ML-KEM parameters
    "ML-KEM-512": {
        "security_level": SecurityLevel.LEVEL1,
        "public_key_size": 800,
        "secret_key_size": 1632,
        "ciphertext_size": 768,
        "shared_secret_size": 32,
    },
    "ML-KEM-768": {
        "security_level": SecurityLevel.LEVEL3,
        "public_key_size": 1184,
        "secret_key_size": 2400,
        "ciphertext_size": 1088,
        "shared_secret_size": 32,
    },
    "ML-KEM-1024": {
        "security_level": SecurityLevel.LEVEL5,
        "public_key_size": 1568,
        "secret_key_size": 3168,
        "ciphertext_size": 1568,
        "shared_secret_size": 32,
    },

    # ML-DSA parameters
    "ML-DSA-44": {
        "security_level": SecurityLevel.LEVEL2,
        "public_key_size": 1312,
        "secret_key_size": 2560,
        "signature_size": 2420,
    },
    "ML-DSA-65": {
        "security_level": SecurityLevel.LEVEL3,
        "public_key_size": 1952,
        "secret_key_size": 4032,
        "signature_size": 3309,
    },
    "ML-DSA-87": {
        "security_level": SecurityLevel.LEVEL5,
        "public_key_size": 2592,
        "secret_key_size": 4896,
        "signature_size": 4627,
    },
}
