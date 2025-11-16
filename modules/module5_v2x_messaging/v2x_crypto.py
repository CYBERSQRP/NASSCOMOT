"""
V2X Cryptographic Operations

Unified cryptographic manager for V2X communication (C-V2X and DSRC).
Provides common crypto operations for vehicle-to-everything communication.
"""

from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
from loguru import logger

from ..module1_pqc_layer.mlkem import MLKEM768
from ..module1_pqc_layer.mldsa import MLDSA65
from ..module3_entropy_rng.secure_random import SecureRandom


@dataclass
class V2XCertificate:
    """V2X pseudonymous certificate."""
    cert_id: bytes
    vehicle_id: str
    public_key: bytes
    valid_from: datetime
    valid_until: datetime
    issuer: str


class V2XCryptoManager:
    """
    Manages V2X cryptographic operations.

    Features:
    - Unified crypto for C-V2X and DSRC
    - Pseudonymous certificate management
    - Message signing and verification
    - Key rotation support
    """

    def __init__(self, vehicle_id: str):
        """
        Initialize V2X crypto manager.

        Args:
            vehicle_id: Vehicle identifier
        """
        self.vehicle_id = vehicle_id

        # Initialize PQC crypto (ML-DSA-65 for V2X signatures)
        self.signer = MLDSA65()
        self.kem = MLKEM768()
        self.rng = SecureRandom()

        # Generate long-term keys
        self.sign_pk, self.sign_sk = self.signer.keygen()
        self.kem_pk, self.kem_sk = self.kem.keygen()

        # Pseudonymous certificates (rotated periodically)
        self.certificates: list[V2XCertificate] = []
        self.current_cert_index = 0

        # Trusted certificate authorities
        self.trusted_ca_keys: Dict[str, bytes] = {}

        logger.info(f"V2X crypto initialized for vehicle: {vehicle_id}")

    def sign_v2x_message(self, message: bytes) -> bytes:
        """
        Sign V2X message with current certificate.

        Args:
            message: Message data to sign

        Returns:
            Digital signature
        """
        return self.signer.sign(self.sign_sk, message)

    def verify_v2x_message(
        self,
        message: bytes,
        signature: bytes,
        sender_pk: bytes
    ) -> bool:
        """
        Verify V2X message signature.

        Args:
            message: Message data
            signature: Digital signature
            sender_pk: Sender's public key

        Returns:
            True if signature valid
        """
        return self.signer.verify(sender_pk, message, signature)

    def generate_pseudonym_certificate(
        self,
        issuer: str,
        validity_days: int = 7
    ) -> V2XCertificate:
        """
        Generate pseudonymous certificate for privacy.

        Certificates are rotated regularly to prevent tracking.

        Args:
            issuer: Certificate authority name
            validity_days: Certificate validity in days

        Returns:
            New pseudonymous certificate
        """
        # Generate ephemeral signing key pair
        ephemeral_pk, ephemeral_sk = self.signer.keygen()

        # Create certificate
        cert = V2XCertificate(
            cert_id=self.rng.random_bytes(8),
            vehicle_id=self.vehicle_id,
            public_key=ephemeral_pk,
            valid_from=datetime.now(),
            valid_until=datetime.now() + timedelta(days=validity_days),
            issuer=issuer
        )

        self.certificates.append(cert)
        logger.info(f"Generated pseudonym certificate: {cert.cert_id.hex()}")

        return cert

    def rotate_certificate(self) -> Optional[V2XCertificate]:
        """
        Rotate to next pseudonymous certificate.

        Returns:
            New active certificate or None if no certificates
        """
        if not self.certificates:
            return None

        self.current_cert_index = (self.current_cert_index + 1) % len(self.certificates)
        cert = self.certificates[self.current_cert_index]

        logger.info(f"Rotated to certificate: {cert.cert_id.hex()}")
        return cert

    def get_current_certificate(self) -> Optional[V2XCertificate]:
        """Get currently active certificate."""
        if not self.certificates:
            return None
        return self.certificates[self.current_cert_index]

    def add_trusted_ca(self, ca_name: str, ca_public_key: bytes) -> None:
        """
        Add trusted certificate authority.

        Args:
            ca_name: CA identifier
            ca_public_key: CA's public key
        """
        self.trusted_ca_keys[ca_name] = ca_public_key
        logger.info(f"Added trusted CA: {ca_name}")

    def derive_group_key(
        self,
        group_id: str,
        members: list[bytes]
    ) -> bytes:
        """
        Derive group key for V2X groupcast.

        Args:
            group_id: Group identifier
            members: List of member public keys

        Returns:
            Derived group key
        """
        # Simple group key derivation (production should use proper group key agreement)
        data = group_id.encode()
        for member_pk in sorted(members):
            data += member_pk

        group_key = hashlib.sha384(data).digest()
        logger.info(f"Derived group key for: {group_id}")

        return group_key

    def sign_with_certificate(
        self,
        message: bytes,
        cert: V2XCertificate
    ) -> Tuple[bytes, bytes]:
        """
        Sign message and include certificate.

        Args:
            message: Message to sign
            cert: Certificate to use

        Returns:
            (signature, serialized_certificate)
        """
        # Sign message
        signature = self.signer.sign(self.sign_sk, message)

        # Serialize certificate (simplified)
        cert_data = (
            cert.cert_id +
            cert.vehicle_id.encode('utf-8').ljust(32, b'\x00') +
            cert.public_key
        )

        return (signature, cert_data)

    def cleanup_expired_certificates(self) -> int:
        """
        Remove expired certificates.

        Returns:
            Number of certificates removed
        """
        now = datetime.now()
        before_count = len(self.certificates)

        self.certificates = [
            cert for cert in self.certificates
            if cert.valid_until > now
        ]

        removed = before_count - len(self.certificates)
        if removed > 0:
            logger.info(f"Removed {removed} expired certificates")

        return removed

    def get_statistics(self) -> Dict:
        """Get V2X crypto statistics."""
        return {
            'vehicle_id': self.vehicle_id,
            'certificates': len(self.certificates),
            'current_cert_index': self.current_cert_index,
            'trusted_cas': len(self.trusted_ca_keys)
        }


__all__ = ['V2XCryptoManager', 'V2XCertificate']
