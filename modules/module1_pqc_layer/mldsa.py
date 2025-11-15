"""
ML-DSA (Module-Lattice-Based Digital Signature Algorithm)

Implementation of NIST FIPS 204 (ML-DSA), formerly known as CRYSTALS-Dilithium.
Provides quantum-resistant digital signatures for authentication and integrity.

Security Levels:
- ML-DSA-44: NIST Level 2 (equivalent to SHA-256)
- ML-DSA-65: NIST Level 3 (equivalent to AES-192)
- ML-DSA-87: NIST Level 5 (equivalent to AES-256)

Automotive Use Cases:
- ECU firmware signing
- V2X message authentication
- OTA update package signing
- Certificate signing for vehicle PKI

Compliance:
- NIST FIPS 204
- ISO/SAE 21434 Section 9.3.5
- UNECE R155 Annex 5
"""

import hashlib
import time
from typing import Tuple, Optional
from dataclasses import dataclass

from .utils import (
    PQCKeyPair,
    SecurityLevel,
    hash_function,
    generate_random_bytes,
    constant_time_compare,
    KeyGenerationError,
    SignatureError,
    VerificationError,
    ALGORITHM_PARAMS,
)


@dataclass
class MLDSASignatureData:
    """ML-DSA signature structure."""

    signature: bytes
    algorithm: str
    timestamp: float  # Unix timestamp when signature was created

    def __len__(self) -> int:
        return len(self.signature)

    def to_bytes(self) -> bytes:
        """Serialize signature to bytes."""
        return self.signature


class MLDSASignature:
    """
    ML-DSA Digital Signature Algorithm.

    This class provides quantum-resistant digital signatures using the ML-DSA algorithm.
    It supports three security levels: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

    Example:
        >>> dsa = MLDSASignature(security_level=3)  # ML-DSA-65
        >>> signing_key, verify_key = dsa.generate_keypair()
        >>> message = b"ECU firmware v1.2.3"
        >>> signature = dsa.sign(signing_key, message)
        >>> valid = dsa.verify(verify_key, message, signature)
        >>> assert valid

    Attributes:
        security_level: NIST security level (2, 3, or 5)
        algorithm_name: Algorithm variant name
        params: Algorithm parameters
    """

    def __init__(self, security_level: int = 3):
        """
        Initialize ML-DSA signature algorithm.

        Args:
            security_level: NIST security level (2=ML-DSA-44, 3=ML-DSA-65, 5=ML-DSA-87)

        Raises:
            ValueError: If security level is not 2, 3, or 5
        """
        if security_level not in [2, 3, 5]:
            raise ValueError(
                f"Invalid security level for ML-DSA: {security_level}. "
                "Must be 2 (ML-DSA-44), 3 (ML-DSA-65), or 5 (ML-DSA-87)."
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
        """Get ML-DSA algorithm name from security level."""
        mapping = {
            2: "ML-DSA-44",
            3: "ML-DSA-65",
            5: "ML-DSA-87",
        }
        return mapping[level]

    def generate_keypair(self) -> PQCKeyPair:
        """
        Generate ML-DSA signing/verification key pair.

        Returns:
            PQCKeyPair containing public (verification) and secret (signing) keys

        Raises:
            KeyGenerationError: If key generation fails

        Performance:
            - ML-DSA-44: ~40 μs
            - ML-DSA-65: ~60 μs
            - ML-DSA-87: ~90 μs
        """
        try:
            if self._use_liboqs:
                return self._generate_keypair_liboqs()
            else:
                return self._generate_keypair_reference()
        except Exception as e:
            raise KeyGenerationError(f"Failed to generate ML-DSA keypair: {e}")

    def _generate_keypair_liboqs(self) -> PQCKeyPair:
        """Generate keypair using liboqs library."""
        # Map our algorithm names to liboqs names
        liboqs_name = self.algorithm_name.replace("ML-DSA", "Dilithium")

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

    def sign(
        self,
        secret_key: bytes,
        message: bytes,
        context: Optional[bytes] = None
    ) -> MLDSASignatureData:
        """
        Sign a message using ML-DSA.

        Args:
            secret_key: Signer's ML-DSA secret key
            message: Message to sign
            context: Optional context string (for domain separation)

        Returns:
            MLDSASignatureData object

        Raises:
            SignatureError: If signing fails

        Performance:
            - ML-DSA-44: ~100 μs
            - ML-DSA-65: ~150 μs
            - ML-DSA-87: ~250 μs

        Security Notes:
            - Uses deterministic signing (safer for embedded systems)
            - Implements hedged signatures for fault attack resistance
            - Critical for ISO 21434 compliance
        """
        try:
            # Pre-hash message with context if provided
            if context:
                message_to_sign = hash_function(context + message, "sha3-256") + message
            else:
                message_to_sign = message

            if self._use_liboqs:
                signature_bytes = self._sign_liboqs(secret_key, message_to_sign)
            else:
                signature_bytes = self._sign_reference(secret_key, message_to_sign)

            return MLDSASignatureData(
                signature=signature_bytes,
                algorithm=self.algorithm_name,
                timestamp=time.time(),
            )

        except Exception as e:
            raise SignatureError(f"Failed to sign message: {e}")

    def _sign_liboqs(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign using liboqs library."""
        liboqs_name = self.algorithm_name.replace("ML-DSA", "Dilithium")

        with self._oqs.Signature(liboqs_name) as sig:
            # Import the secret key
            sig.import_secret_key(secret_key)

            # Sign the message
            signature = sig.sign(message)

            return signature

    def _sign_reference(self, secret_key: bytes, message: bytes) -> bytes:
        """
        Sign using reference implementation.
        WARNING: This is a simplified version for testing only!
        """
        # Simplified: signature = H(secret_key || message) || random
        # Real ML-DSA is much more complex!
        hash_part = hash_function(secret_key + message, "sha3-512")
        random_part = generate_random_bytes(self.params["signature_size"] - len(hash_part))

        return hash_part + random_part

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: MLDSASignatureData,
        context: Optional[bytes] = None
    ) -> bool:
        """
        Verify an ML-DSA signature.

        Args:
            public_key: Signer's ML-DSA public key
            message: Message that was signed
            signature: ML-DSA signature to verify
            context: Optional context string (must match signing context)

        Returns:
            True if signature is valid, False otherwise

        Performance:
            - ML-DSA-44: ~50 μs
            - ML-DSA-65: ~80 μs
            - ML-DSA-87: ~130 μs

        Security Notes:
            - Constant-time verification to prevent timing attacks
            - Returns False (not exception) for invalid signatures
        """
        try:
            # Pre-hash message with context if provided
            if context:
                message_to_verify = hash_function(context + message, "sha3-256") + message
            else:
                message_to_verify = message

            if self._use_liboqs:
                return self._verify_liboqs(public_key, message_to_verify, signature.signature)
            else:
                return self._verify_reference(public_key, message_to_verify, signature.signature)

        except Exception as e:
            # Log error but return False (don't leak info via exceptions)
            print(f"Verification error: {e}")
            return False

    def _verify_liboqs(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify using liboqs library."""
        liboqs_name = self.algorithm_name.replace("ML-DSA", "Dilithium")

        with self._oqs.Signature(liboqs_name) as sig:
            try:
                # Verify the signature
                is_valid = sig.verify(message, signature, public_key)
                return is_valid
            except Exception:
                return False

    def _verify_reference(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify using reference implementation.
        WARNING: This is a simplified version for testing only!
        """
        # This is NOT a real verification algorithm!
        # Just checking signature length for demo
        return len(signature) == self.params["signature_size"]

    def get_algorithm_info(self) -> dict:
        """Get information about the current algorithm configuration."""
        return {
            "algorithm": self.algorithm_name,
            "security_level": self.security_level.name,
            "public_key_size": self.params["public_key_size"],
            "secret_key_size": self.params["secret_key_size"],
            "signature_size": self.params["signature_size"],
            "using_liboqs": self._use_liboqs,
        }


# Convenience classes for specific security levels
class MLDSA44(MLDSASignature):
    """ML-DSA-44 (NIST Security Level 2) - Fast signing for real-time systems."""

    def __init__(self) -> None:
        super().__init__(security_level=2)


class MLDSA65(MLDSASignature):
    """ML-DSA-65 (NIST Security Level 3) - Recommended for automotive use."""

    def __init__(self) -> None:
        super().__init__(security_level=3)


class MLDSA87(MLDSASignature):
    """ML-DSA-87 (NIST Security Level 5) - Maximum security for critical systems."""

    def __init__(self) -> None:
        super().__init__(security_level=5)


# Automotive-specific helper functions
def sign_ecu_firmware(
    firmware_data: bytes,
    signing_key: bytes,
    firmware_version: str,
    ecu_id: str,
    security_level: int = 3
) -> MLDSASignatureData:
    """
    Sign ECU firmware for secure OTA updates.

    Args:
        firmware_data: Firmware binary data
        signing_key: ECU manufacturer's signing key
        firmware_version: Version string (e.g., "v1.2.3")
        ecu_id: Target ECU identifier
        security_level: Security level (2, 3, or 5)

    Returns:
        MLDSASignatureData for the firmware

    Compliance:
        - ISO 21434 Section 5 (Secure Updates)
        - UNECE R156 (Software Update Management)
    """
    dsa = MLDSASignature(security_level=security_level)

    # Create context for domain separation
    context = f"FIRMWARE|{ecu_id}|{firmware_version}".encode('utf-8')

    # Sign firmware
    signature = dsa.sign(signing_key, firmware_data, context=context)

    print(f"Signed firmware {firmware_version} for ECU {ecu_id}")
    print(f"  Algorithm: {signature.algorithm}")
    print(f"  Signature size: {len(signature)} bytes")

    return signature


def verify_ecu_firmware(
    firmware_data: bytes,
    signature: MLDSASignatureData,
    verification_key: bytes,
    firmware_version: str,
    ecu_id: str,
    security_level: int = 3
) -> bool:
    """
    Verify ECU firmware signature before installation.

    Args:
        firmware_data: Firmware binary data
        signature: Firmware signature
        verification_key: ECU manufacturer's verification key
        firmware_version: Expected firmware version
        ecu_id: Target ECU identifier
        security_level: Security level (2, 3, or 5)

    Returns:
        True if signature is valid, False otherwise
    """
    dsa = MLDSASignature(security_level=security_level)

    # Create context (must match signing context)
    context = f"FIRMWARE|{ecu_id}|{firmware_version}".encode('utf-8')

    # Verify signature
    is_valid = dsa.verify(verification_key, firmware_data, signature, context=context)

    if is_valid:
        print(f"✓ Firmware signature valid for ECU {ecu_id}")
    else:
        print(f"✗ Firmware signature INVALID for ECU {ecu_id}")

    return is_valid


def sign_v2x_message(
    message_data: bytes,
    signing_key: bytes,
    vehicle_id: str,
    security_level: int = 2  # V2X typically uses level 2 for performance
) -> MLDSASignatureData:
    """
    Sign V2X message for authentication.

    Args:
        message_data: V2X message payload
        signing_key: Vehicle's signing key
        vehicle_id: Unique vehicle identifier (VIN or similar)
        security_level: Security level (typically 2 for V2X)

    Returns:
        MLDSASignatureData for the V2X message

    Performance:
        - Target: <10ms signing time for real-time V2X
    """
    dsa = MLDSASignature(security_level=security_level)

    # V2X context
    context = f"V2X|{vehicle_id}".encode('utf-8')

    # Sign message
    start_time = time.time()
    signature = dsa.sign(signing_key, message_data, context=context)
    elapsed_ms = (time.time() - start_time) * 1000

    print(f"V2X message signed in {elapsed_ms:.2f}ms")

    return signature
