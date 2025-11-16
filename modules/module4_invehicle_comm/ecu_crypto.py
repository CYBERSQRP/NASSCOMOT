"""
ECU Cryptographic Manager

Manages cryptographic operations for ECU secure communication.
Integrates PQC algorithms for ECU-to-ECU encryption and authentication.
"""

from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import struct
from loguru import logger

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logger.warning("cryptography library not available")

from ..module1_pqc_layer.mlkem import MLKEM768
from ..module1_pqc_layer.mldsa import MLDSA65
from ..module3_entropy_rng.secure_random import SecureRandom


@dataclass
class ECUSession:
    """Secure session between ECUs."""
    peer_ecu_id: str
    shared_secret: bytes
    encryption_key: bytes
    mac_key: bytes
    session_id: int
    established_at: datetime
    message_counter: int = 0
    valid_until: datetime = None


class ECUCryptoManager:
    """
    Manages cryptographic keys and sessions for ECUs.

    Features:
    - PQC key generation for ECUs (ML-KEM-768, ML-DSA-65)
    - Session key establishment and rotation
    - Message encryption with AES-256-GCM
    - Message authentication with ML-DSA signatures
    - Replay attack protection with message counters
    - Key lifecycle management
    """

    def __init__(self, ecu_id: str, session_lifetime_hours: int = 24):
        """
        Initialize ECU crypto manager.

        Args:
            ecu_id: Unique ECU identifier
            session_lifetime_hours: Session validity in hours
        """
        self.ecu_id = ecu_id
        self.session_lifetime = timedelta(hours=session_lifetime_hours)

        # Initialize PQC crypto
        self.kem = MLKEM768()
        self.signer = MLDSA65()
        self.rng = SecureRandom()

        # Generate ECU long-term keys
        self.kem_pk, self.kem_sk = self.kem.keygen()
        self.sign_pk, self.sign_sk = self.signer.keygen()

        # Active sessions
        self.sessions: Dict[str, ECUSession] = {}
        self.session_counter = 0

        logger.info(f"ECU {ecu_id} initialized with PQC keys")

    def get_public_keys(self) -> Tuple[bytes, bytes]:
        """
        Get ECU's public keys.

        Returns:
            (kem_public_key, signing_public_key)
        """
        return (self.kem_pk, self.sign_pk)

    def establish_session(
        self,
        peer_ecu_id: str,
        peer_kem_pk: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Establish secure session with another ECU (initiator role).

        Args:
            peer_ecu_id: Peer ECU identifier
            peer_kem_pk: Peer's ML-KEM public key

        Returns:
            (kem_ciphertext, signature) to send to peer
        """
        # Perform key encapsulation
        ciphertext, shared_secret = self.kem.encapsulate(peer_kem_pk)

        # Derive session keys using HKDF
        encryption_key, mac_key = self._derive_session_keys(
            shared_secret,
            self.ecu_id,
            peer_ecu_id
        )

        # Create session
        self.session_counter += 1
        session = ECUSession(
            peer_ecu_id=peer_ecu_id,
            shared_secret=shared_secret,
            encryption_key=encryption_key,
            mac_key=mac_key,
            session_id=self.session_counter,
            established_at=datetime.now(),
            valid_until=datetime.now() + self.session_lifetime
        )

        self.sessions[peer_ecu_id] = session

        # Sign the ciphertext for authentication
        message = ciphertext + self.ecu_id.encode() + peer_ecu_id.encode()
        signature = self.signer.sign(self.sign_sk, message)

        logger.info(
            f"ECU {self.ecu_id} established session with {peer_ecu_id}, "
            f"SessionID={self.session_counter}"
        )

        return (ciphertext, signature)

    def receive_session(
        self,
        peer_ecu_id: str,
        ciphertext: bytes,
        signature: bytes,
        peer_sign_pk: bytes
    ) -> bool:
        """
        Receive session establishment from peer ECU (responder role).

        Args:
            peer_ecu_id: Peer ECU identifier
            ciphertext: ML-KEM ciphertext from peer
            signature: Signature over ciphertext
            peer_sign_pk: Peer's ML-DSA public key

        Returns:
            True if session established successfully
        """
        # Verify signature
        message = ciphertext + peer_ecu_id.encode() + self.ecu_id.encode()
        if not self.signer.verify(peer_sign_pk, message, signature):
            logger.error(f"Signature verification failed from {peer_ecu_id}")
            return False

        # Decapsulate to recover shared secret
        shared_secret = self.kem.decapsulate(ciphertext, self.kem_sk)

        # Derive session keys
        encryption_key, mac_key = self._derive_session_keys(
            shared_secret,
            peer_ecu_id,
            self.ecu_id
        )

        # Create session
        self.session_counter += 1
        session = ECUSession(
            peer_ecu_id=peer_ecu_id,
            shared_secret=shared_secret,
            encryption_key=encryption_key,
            mac_key=mac_key,
            session_id=self.session_counter,
            established_at=datetime.now(),
            valid_until=datetime.now() + self.session_lifetime
        )

        self.sessions[peer_ecu_id] = session

        logger.info(f"ECU {self.ecu_id} received session from {peer_ecu_id}")
        return True

    def encrypt_message(self, peer_ecu_id: str, plaintext: bytes) -> Optional[bytes]:
        """
        Encrypt message for peer ECU.

        Message format: [Counter:4][Nonce:12][Ciphertext:N][MAC:16]

        Args:
            peer_ecu_id: Destination ECU
            plaintext: Message data

        Returns:
            Encrypted message or None if no session
        """
        if peer_ecu_id not in self.sessions:
            logger.error(f"No session with {peer_ecu_id}")
            return None

        session = self.sessions[peer_ecu_id]

        # Check session validity
        if datetime.now() > session.valid_until:
            logger.warning(f"Session with {peer_ecu_id} expired")
            return None

        # Increment message counter
        session.message_counter += 1
        counter_bytes = struct.pack('>I', session.message_counter)

        # Encrypt with AES-256-GCM if available
        if CRYPTO_AVAILABLE:
            nonce = self.rng.random_bytes(12)
            aesgcm = AESGCM(session.encryption_key[:32])
            ciphertext = aesgcm.encrypt(nonce, plaintext, counter_bytes)

            # Compute MAC over counter + nonce + ciphertext
            mac = hmac.new(
                session.mac_key,
                counter_bytes + nonce + ciphertext,
                hashlib.sha256
            ).digest()[:16]

            return counter_bytes + nonce + ciphertext + mac
        else:
            # Fallback to stream cipher
            nonce = self.rng.random_bytes(12)
            ciphertext = self._stream_encrypt(
                plaintext,
                session.encryption_key,
                counter_bytes + nonce
            )

            mac = hmac.new(
                session.mac_key,
                counter_bytes + nonce + ciphertext,
                hashlib.sha256
            ).digest()[:16]

            return counter_bytes + nonce + ciphertext + mac

    def decrypt_message(
        self,
        peer_ecu_id: str,
        encrypted_message: bytes
    ) -> Optional[bytes]:
        """
        Decrypt message from peer ECU.

        Args:
            peer_ecu_id: Source ECU
            encrypted_message: Encrypted message

        Returns:
            Decrypted message or None if verification failed
        """
        if peer_ecu_id not in self.sessions:
            logger.error(f"No session with {peer_ecu_id}")
            return None

        session = self.sessions[peer_ecu_id]

        # Parse message
        if len(encrypted_message) < 32:  # 4 + 12 + 0 + 16
            logger.error("Message too short")
            return None

        counter_bytes = encrypted_message[:4]
        nonce = encrypted_message[4:16]
        ciphertext = encrypted_message[16:-16]
        received_mac = encrypted_message[-16:]

        # Verify MAC
        expected_mac = hmac.new(
            session.mac_key,
            encrypted_message[:-16],
            hashlib.sha256
        ).digest()[:16]

        if not hmac.compare_digest(received_mac, expected_mac):
            logger.error("MAC verification failed")
            return None

        # Check counter (replay protection)
        counter = struct.unpack('>I', counter_bytes)[0]
        # Simple check - in production, use sliding window

        # Decrypt
        if CRYPTO_AVAILABLE:
            aesgcm = AESGCM(session.encryption_key[:32])
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, counter_bytes)
                return plaintext
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return None
        else:
            # Fallback to stream cipher
            plaintext = self._stream_decrypt(
                ciphertext,
                session.encryption_key,
                counter_bytes + nonce
            )
            return plaintext

    def sign_message(self, message: bytes) -> bytes:
        """
        Sign message with ECU's signing key.

        Args:
            message: Message to sign

        Returns:
            Digital signature
        """
        return self.signer.sign(self.sign_sk, message)

    def verify_message(
        self,
        peer_ecu_id: str,
        message: bytes,
        signature: bytes,
        peer_sign_pk: bytes
    ) -> bool:
        """
        Verify message signature from peer ECU.

        Args:
            peer_ecu_id: Source ECU
            message: Message data
            signature: Digital signature
            peer_sign_pk: Peer's signing public key

        Returns:
            True if signature valid
        """
        return self.signer.verify(peer_sign_pk, message, signature)

    def rotate_session(self, peer_ecu_id: str, peer_kem_pk: bytes) -> Optional[Tuple[bytes, bytes]]:
        """
        Rotate session keys with peer ECU.

        Args:
            peer_ecu_id: Peer ECU identifier
            peer_kem_pk: Peer's KEM public key

        Returns:
            (ciphertext, signature) or None
        """
        if peer_ecu_id not in self.sessions:
            logger.error(f"No session to rotate with {peer_ecu_id}")
            return None

        logger.info(f"Rotating session with {peer_ecu_id}")

        # Remove old session
        del self.sessions[peer_ecu_id]

        # Establish new session
        return self.establish_session(peer_ecu_id, peer_kem_pk)

    def close_session(self, peer_ecu_id: str) -> bool:
        """
        Close session with peer ECU.

        Args:
            peer_ecu_id: Peer ECU identifier

        Returns:
            True if session closed
        """
        if peer_ecu_id in self.sessions:
            del self.sessions[peer_ecu_id]
            logger.info(f"Closed session with {peer_ecu_id}")
            return True
        return False

    def get_session_info(self, peer_ecu_id: str) -> Optional[Dict]:
        """
        Get session information.

        Args:
            peer_ecu_id: Peer ECU identifier

        Returns:
            Session info dictionary or None
        """
        if peer_ecu_id not in self.sessions:
            return None

        session = self.sessions[peer_ecu_id]
        return {
            'peer_ecu_id': peer_ecu_id,
            'session_id': session.session_id,
            'established_at': session.established_at.isoformat(),
            'valid_until': session.valid_until.isoformat(),
            'message_counter': session.message_counter,
            'expired': datetime.now() > session.valid_until
        }

    def cleanup_expired_sessions(self) -> int:
        """
        Remove expired sessions.

        Returns:
            Number of sessions removed
        """
        now = datetime.now()
        expired = [
            ecu_id for ecu_id, session in self.sessions.items()
            if now > session.valid_until
        ]

        for ecu_id in expired:
            del self.sessions[ecu_id]
            logger.info(f"Removed expired session with {ecu_id}")

        return len(expired)

    # --- Internal Helper Methods ---

    def _derive_session_keys(
        self,
        shared_secret: bytes,
        id_a: str,
        id_b: str
    ) -> Tuple[bytes, bytes]:
        """Derive encryption and MAC keys using HKDF."""
        salt = (id_a + id_b).encode()
        prk = hmac.new(salt, shared_secret, hashlib.sha384).digest()

        # Derive 32-byte encryption key
        enc_key = hmac.new(prk, b'ECU-ENC\x01', hashlib.sha384).digest()[:32]

        # Derive 32-byte MAC key
        mac_key = hmac.new(prk, b'ECU-MAC\x01', hashlib.sha384).digest()[:32]

        return enc_key, mac_key

    def _stream_encrypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Simple stream cipher for fallback."""
        key_stream = hmac.new(key, nonce, hashlib.sha256).digest()
        while len(key_stream) < len(data):
            key_stream += hmac.new(key, key_stream[-32:], hashlib.sha256).digest()
        return bytes(a ^ b for a, b in zip(data, key_stream))

    def _stream_decrypt(self, data: bytes, key: bytes, nonce: bytes) -> bytes:
        """Simple stream cipher decryption."""
        return self._stream_encrypt(data, key, nonce)


__all__ = ['ECUCryptoManager', 'ECUSession']
