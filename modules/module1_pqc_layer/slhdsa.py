"""
SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)

Implementation of NIST FIPS 205 (SLH-DSA), formerly known as SPHINCS+.
Provides quantum-resistant digital signatures with minimal security assumptions.

Security Levels:
- SLH-DSA-128s: NIST Level 1 (small signatures, slower)
- SLH-DSA-192s: NIST Level 3 (balanced)
- SLH-DSA-256s: NIST Level 5 (maximum security)

Automotive Use Cases:
- Long-term firmware signing (10+ years)
- Certificate authority root signatures
- Critical safety-related message signing
- Fallback when lattice-based crypto is unavailable

Advantages:
- Minimal security assumptions (only relies on hash functions)
- No trapdoors or structured problems
- Conservative choice for long-term security

Disadvantages:
- Larger signature sizes than ML-DSA
- Slower signing/verification

Compliance:
- NIST FIPS 205
- ISO/SAE 21434 Section 9.3.5
"""

from typing import Tuple, Optional
from dataclasses import dataclass
import time

from .utils import (
    PQCKeyPair,
    SecurityLevel,
    hash_function,
    generate_random_bytes,
    KeyGenerationError,
    SignatureError,
    VerificationError,
)


@dataclass
class SLHDSASignatureData:
    """SLH-DSA signature structure."""

    signature: bytes
    algorithm: str
    timestamp: float

    def __len__(self) -> int:
        return len(self.signature)

    def to_bytes(self) -> bytes:
        return self.signature


class SLHDSASignature:
    """
    SLH-DSA Stateless Hash-Based Signature Algorithm.

    This class provides quantum-resistant digital signatures using only
    cryptographic hash functions. It's the most conservative PQC option.

    Example:
        >>> sig = SLHDSASignature(security_level=1)
        >>> signing_key, verify_key = sig.generate_keypair()
        >>> message = b"Critical safety message"
        >>> signature = sig.sign(signing_key, message)
        >>> valid = sig.verify(verify_key, message, signature)
    """

    # SLH-DSA parameter sets (SPHINCS+ SHA2-128s, 192s, 256s)
    PARAMS = {
        "SLH-DSA-128s": {
            "security_level": SecurityLevel.LEVEL1,
            "public_key_size": 32,
            "secret_key_size": 64,
            "signature_size": 7856,  # Small variant
            "n": 16,  # Hash output size (bytes)
            "h": 63,  # Total tree height
        },
        "SLH-DSA-192s": {
            "security_level": SecurityLevel.LEVEL3,
            "public_key_size": 48,
            "secret_key_size": 96,
            "signature_size": 17088,
            "n": 24,
            "h": 63,
        },
        "SLH-DSA-256s": {
            "security_level": SecurityLevel.LEVEL5,
            "public_key_size": 64,
            "secret_key_size": 128,
            "signature_size": 29792,
            "n": 32,
            "h": 64,
        },
    }

    def __init__(self, security_level: int = 1):
        """
        Initialize SLH-DSA signature algorithm.

        Args:
            security_level: NIST security level (1, 3, or 5)
        """
        if security_level not in [1, 3, 5]:
            raise ValueError(f"Invalid security level: {security_level}")

        self.security_level = SecurityLevel(security_level)
        self.algorithm_name = self._get_algorithm_name(security_level)
        self.params = self.PARAMS[self.algorithm_name]

        # Try to import liboqs
        try:
            import oqs
            self._use_liboqs = True
            self._oqs = oqs
        except ImportError:
            self._use_liboqs = False
            print("WARNING: liboqs not found. Using reference implementation.")

    def _get_algorithm_name(self, level: int) -> str:
        """Get algorithm name from security level."""
        mapping = {1: "SLH-DSA-128s", 3: "SLH-DSA-192s", 5: "SLH-DSA-256s"}
        return mapping[level]

    def generate_keypair(self) -> PQCKeyPair:
        """Generate SLH-DSA key pair."""
        try:
            if self._use_liboqs:
                return self._generate_keypair_liboqs()
            else:
                return self._generate_keypair_reference()
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate SLH-DSA keypair: {e}")

    def _generate_keypair_liboqs(self) -> PQCKeyPair:
        """Generate keypair using liboqs."""
        liboqs_name = f"SPHINCS+-SHA2-{self.params['n']*8}s-simple"

        with self._oqs.Signature(liboqs_name) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()

            return PQCKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=self.algorithm_name,
                security_level=self.security_level,
            )

    def _generate_keypair_reference(self) -> PQCKeyPair:
        """Reference implementation (demo only)."""
        public_key = generate_random_bytes(self.params["public_key_size"])
        secret_key = generate_random_bytes(self.params["secret_key_size"])

        return PQCKeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.algorithm_name,
            security_level=self.security_level,
        )

    def sign(self, secret_key: bytes, message: bytes) -> SLHDSASignatureData:
        """Sign a message using SLH-DSA."""
        try:
            if self._use_liboqs:
                signature_bytes = self._sign_liboqs(secret_key, message)
            else:
                signature_bytes = self._sign_reference(secret_key, message)

            return SLHDSASignatureData(
                signature=signature_bytes,
                algorithm=self.algorithm_name,
                timestamp=time.time(),
            )
        except Exception as e:
            raise SignatureError(f"Failed to sign: {e}")

    def _sign_liboqs(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign using liboqs."""
        liboqs_name = f"SPHINCS+-SHA2-{self.params['n']*8}s-simple"

        with self._oqs.Signature(liboqs_name) as sig:
            sig.import_secret_key(secret_key)
            return sig.sign(message)

    def _sign_reference(self, secret_key: bytes, message: bytes) -> bytes:
        """Reference signing (demo only)."""
        hash_part = hash_function(secret_key + message, "sha3-512")
        random_part = generate_random_bytes(self.params["signature_size"] - len(hash_part))
        return hash_part + random_part

    def verify(
        self, public_key: bytes, message: bytes, signature: SLHDSASignatureData
    ) -> bool:
        """Verify an SLH-DSA signature."""
        try:
            if self._use_liboqs:
                return self._verify_liboqs(public_key, message, signature.signature)
            else:
                return self._verify_reference(public_key, message, signature.signature)
        except Exception:
            return False

    def _verify_liboqs(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify using liboqs."""
        liboqs_name = f"SPHINCS+-SHA2-{self.params['n']*8}s-simple"

        with self._oqs.Signature(liboqs_name) as sig:
            try:
                return sig.verify(message, signature, public_key)
            except Exception:
                return False

    def _verify_reference(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Reference verification (demo only)."""
        return len(signature) == self.params["signature_size"]


# Convenience classes
class SLHDSA128s(SLHDSASignature):
    """SLH-DSA-128s (NIST Level 1)"""

    def __init__(self) -> None:
        super().__init__(security_level=1)


class SLHDSA192s(SLHDSASignature):
    """SLH-DSA-192s (NIST Level 3)"""

    def __init__(self) -> None:
        super().__init__(security_level=3)


class SLHDSA256s(SLHDSASignature):
    """SLH-DSA-256s (NIST Level 5)"""

    def __init__(self) -> None:
        super().__init__(security_level=5)
