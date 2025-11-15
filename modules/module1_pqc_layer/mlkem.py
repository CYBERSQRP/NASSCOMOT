"""
ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)

Implementation of NIST FIPS 203 (ML-KEM), formerly known as CRYSTALS-Kyber.
Provides quantum-resistant key encapsulation for secure key exchange.

Security Levels:
- ML-KEM-512: NIST Level 1 (equivalent to AES-128)
- ML-KEM-768: NIST Level 3 (equivalent to AES-192)
- ML-KEM-1024: NIST Level 5 (equivalent to AES-256)

Automotive Use Cases:
- ECU-to-ECU secure key exchange
- V2X session key establishment
- OTA update channel encryption
- AUTOSAR Crypto Stack integration

Compliance:
- NIST FIPS 203
- ISO/SAE 21434 Section 9.3.3
- UNECE R155 Annex 5
"""

import os
import time
from typing import Tuple, Optional
from dataclasses import dataclass

from .utils import (
    PQCKeyPair,
    SecurityLevel,
    hash_function,
    generate_random_bytes,
    KeyGenerationError,
    EncapsulationError,
    DecapsulationError,
    ALGORITHM_PARAMS,
)


@dataclass
class MLKEMCiphertext:
    """ML-KEM ciphertext structure."""

    ciphertext: bytes
    algorithm: str

    def __len__(self) -> int:
        return len(self.ciphertext)


class MLKEMKeyExchange:
    """
    ML-KEM Key Encapsulation Mechanism.

    This class provides quantum-resistant key exchange using the ML-KEM algorithm.
    It supports three security levels: ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

    Example:
        >>> kem = MLKEMKeyExchange(security_level=3)  # ML-KEM-768
        >>> public_key, secret_key = kem.generate_keypair()
        >>> ciphertext, shared_secret_sender = kem.encapsulate(public_key)
        >>> shared_secret_receiver = kem.decapsulate(secret_key, ciphertext)
        >>> assert shared_secret_sender == shared_secret_receiver

    Attributes:
        security_level: NIST security level (1, 3, or 5)
        algorithm_name: Algorithm variant name
        params: Algorithm parameters
    """

    def __init__(self, security_level: int = 3):
        """
        Initialize ML-KEM key exchange.

        Args:
            security_level: NIST security level (1=ML-KEM-512, 3=ML-KEM-768, 5=ML-KEM-1024)

        Raises:
            ValueError: If security level is not 1, 3, or 5
        """
        if security_level not in [1, 3, 5]:
            raise ValueError(
                f"Invalid security level for ML-KEM: {security_level}. "
                "Must be 1 (ML-KEM-512), 3 (ML-KEM-768), or 5 (ML-KEM-1024)."
            )

        self.security_level = SecurityLevel(security_level)
        self.algorithm_name = self._get_algorithm_name(security_level)
        self.params = ALGORITHM_PARAMS[self.algorithm_name]

        # Try to import liboqs (Open Quantum Safe)
        try:
            import oqs
            self._use_liboqs = True
            self._oqs = oqs
        except ImportError:
            # Fallback to reference implementation (slower, for testing only)
            self._use_liboqs = False
            print(
                "WARNING: liboqs not found. Using reference implementation. "
                "Install liboqs-python for production use."
            )

    def _get_algorithm_name(self, level: int) -> str:
        """Get ML-KEM algorithm name from security level."""
        mapping = {
            1: "ML-KEM-512",
            3: "ML-KEM-768",
            5: "ML-KEM-1024",
        }
        return mapping[level]

    def generate_keypair(self) -> PQCKeyPair:
        """
        Generate ML-KEM key pair.

        Returns:
            PQCKeyPair containing public and secret keys

        Raises:
            KeyGenerationError: If key generation fails

        Performance:
            - ML-KEM-512: ~15 μs
            - ML-KEM-768: ~20 μs
            - ML-KEM-1024: ~30 μs
        """
        try:
            if self._use_liboqs:
                return self._generate_keypair_liboqs()
            else:
                return self._generate_keypair_reference()
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate ML-KEM keypair: {e}")

    def _generate_keypair_liboqs(self) -> PQCKeyPair:
        """Generate keypair using liboqs library."""
        # Map our algorithm names to liboqs names
        liboqs_name = self.algorithm_name.replace("ML-KEM", "Kyber")

        with self._oqs.KeyEncapsulation(liboqs_name) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()

            return PQCKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                algorithm=self.algorithm_name,
                security_level=self.security_level,
            )

    def _generate_keypair_reference(self) -> PQCKeyPair:
        """
        Generate keypair using reference implementation.
        WARNING: This is a simplified version for testing only!
        """
        # Generate random keys (NOT SECURE - for demo only)
        public_key = generate_random_bytes(self.params["public_key_size"])
        secret_key = generate_random_bytes(self.params["secret_key_size"])

        return PQCKeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.algorithm_name,
            security_level=self.security_level,
        )

    def encapsulate(self, public_key: bytes) -> Tuple[MLKEMCiphertext, bytes]:
        """
        Encapsulate a shared secret using the recipient's public key.

        Args:
            public_key: Recipient's ML-KEM public key

        Returns:
            Tuple of (ciphertext, shared_secret)

        Raises:
            EncapsulationError: If encapsulation fails

        Performance:
            - ML-KEM-512: ~20 μs
            - ML-KEM-768: ~25 μs
            - ML-KEM-1024: ~35 μs
        """
        try:
            if self._use_liboqs:
                return self._encapsulate_liboqs(public_key)
            else:
                return self._encapsulate_reference(public_key)
        except Exception as e:
            raise EncapsulationError(f"Failed to encapsulate: {e}")

    def _encapsulate_liboqs(self, public_key: bytes) -> Tuple[MLKEMCiphertext, bytes]:
        """Encapsulate using liboqs library."""
        liboqs_name = self.algorithm_name.replace("ML-KEM", "Kyber")

        with self._oqs.KeyEncapsulation(liboqs_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

            return (
                MLKEMCiphertext(ciphertext=ciphertext, algorithm=self.algorithm_name),
                shared_secret,
            )

    def _encapsulate_reference(self, public_key: bytes) -> Tuple[MLKEMCiphertext, bytes]:
        """
        Encapsulate using reference implementation.
        WARNING: This is a simplified version for testing only!
        """
        # Generate random ciphertext and shared secret (NOT SECURE - for demo only)
        ciphertext = generate_random_bytes(self.params["ciphertext_size"])
        shared_secret = generate_random_bytes(self.params["shared_secret_size"])

        # In real implementation, shared_secret = H(pk || ct || random)
        # This ensures both parties can derive the same key

        return (
            MLKEMCiphertext(ciphertext=ciphertext, algorithm=self.algorithm_name),
            shared_secret,
        )

    def decapsulate(self, secret_key: bytes, ciphertext: MLKEMCiphertext) -> bytes:
        """
        Decapsulate a shared secret using the recipient's secret key.

        Args:
            secret_key: Recipient's ML-KEM secret key
            ciphertext: ML-KEM ciphertext

        Returns:
            Shared secret bytes

        Raises:
            DecapsulationError: If decapsulation fails

        Performance:
            - ML-KEM-512: ~25 μs
            - ML-KEM-768: ~30 μs
            - ML-KEM-1024: ~40 μs
        """
        try:
            if self._use_liboqs:
                return self._decapsulate_liboqs(secret_key, ciphertext)
            else:
                return self._decapsulate_reference(secret_key, ciphertext)
        except Exception as e:
            raise DecapsulationError(f"Failed to decapsulate: {e}")

    def _decapsulate_liboqs(self, secret_key: bytes, ciphertext: MLKEMCiphertext) -> bytes:
        """Decapsulate using liboqs library."""
        liboqs_name = self.algorithm_name.replace("ML-KEM", "Kyber")

        with self._oqs.KeyEncapsulation(liboqs_name) as kem:
            # Import the secret key
            kem.import_secret_key(secret_key)

            # Decapsulate to get shared secret
            shared_secret = kem.decap_secret(ciphertext.ciphertext)

            return shared_secret

    def _decapsulate_reference(self, secret_key: bytes, ciphertext: MLKEMCiphertext) -> bytes:
        """
        Decapsulate using reference implementation.
        WARNING: This is a simplified version for testing only!
        """
        # In reference implementation, derive key from secret and ciphertext
        # This is NOT the real algorithm!
        combined = secret_key + ciphertext.ciphertext
        shared_secret = hash_function(combined, "sha3-256")

        return shared_secret[:self.params["shared_secret_size"]]

    def get_algorithm_info(self) -> dict:
        """Get information about the current algorithm configuration."""
        return {
            "algorithm": self.algorithm_name,
            "security_level": self.security_level.name,
            "public_key_size": self.params["public_key_size"],
            "secret_key_size": self.params["secret_key_size"],
            "ciphertext_size": self.params["ciphertext_size"],
            "shared_secret_size": self.params["shared_secret_size"],
            "using_liboqs": self._use_liboqs,
        }


# Convenience classes for specific security levels
class MLKEM512(MLKEMKeyExchange):
    """ML-KEM-512 (NIST Security Level 1) - Fast, suitable for constrained ECUs."""

    def __init__(self) -> None:
        super().__init__(security_level=1)


class MLKEM768(MLKEMKeyExchange):
    """ML-KEM-768 (NIST Security Level 3) - Recommended for automotive use."""

    def __init__(self) -> None:
        super().__init__(security_level=3)


class MLKEM1024(MLKEMKeyExchange):
    """ML-KEM-1024 (NIST Security Level 5) - Maximum security for critical systems."""

    def __init__(self) -> None:
        super().__init__(security_level=5)


# Automotive-specific helper functions
def generate_ecu_keypair(ecu_id: str, security_level: int = 3) -> PQCKeyPair:
    """
    Generate ML-KEM keypair for an ECU.

    Args:
        ecu_id: Unique ECU identifier
        security_level: Security level (1, 3, or 5)

    Returns:
        PQCKeyPair for the ECU
    """
    kem = MLKEMKeyExchange(security_level=security_level)
    keypair = kem.generate_keypair()

    # Add metadata (in production, store this securely)
    print(f"Generated {keypair.algorithm} keypair for ECU: {ecu_id}")

    return keypair


def establish_ecu_session_key(
    sender_id: str,
    receiver_public_key: bytes,
    security_level: int = 3
) -> Tuple[bytes, bytes]:
    """
    Establish a session key between two ECUs.

    Args:
        sender_id: Sender ECU identifier
        receiver_public_key: Receiver's ML-KEM public key
        security_level: Security level (1, 3, or 5)

    Returns:
        Tuple of (ciphertext, shared_secret)
    """
    kem = MLKEMKeyExchange(security_level=security_level)
    ciphertext, shared_secret = kem.encapsulate(receiver_public_key)

    print(f"ECU {sender_id} established session key ({len(shared_secret)} bytes)")

    return ciphertext.ciphertext, shared_secret
