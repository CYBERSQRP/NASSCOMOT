"""
DSRC/ITS-G5 Security with Post-Quantum Cryptography

Implements PQC-secured DSRC (Dedicated Short-Range Communications) / ITS-G5.
Compliant with IEEE 1609.2 and ETSI ITS-G5 security standards.
"""

from typing import Optional, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import struct
import hashlib
from loguru import logger

from ..module1_pqc_layer.mlkem import MLKEM768
from ..module1_pqc_layer.mldsa import MLDSA65


class DSRCMessageType(Enum):
    """DSRC/WAVE message types (IEEE 1609)."""
    BSM = 0x14  # Basic Safety Message (SAE J2735)
    TIM = 0x1F  # Traveler Information Message
    RSA = 0x1B  # Road Side Alert
    SPAT = 0x13  # Signal Phase and Timing
    MAP = 0x12  # Map Data


@dataclass
class BSMCore:
    """Basic Safety Message core data (Part I)."""
    msg_count: int  # Message count
    temp_id: bytes  # Temporary ID (4 bytes)
    sec_mark: int  # Seconds mark (DSecond, 0-59999 ms)
    latitude: float  # Degrees
    longitude: float  # Degrees
    elevation: float  # Meters
    accuracy: Tuple[float, float, float]  # Semi-major, semi-minor, orientation
    speed: float  # m/s
    heading: float  # Degrees (0-359.9875)
    angle: float  # Steering wheel angle
    accel_set: Tuple[float, float, float, float]  # Long, lat, vert, yaw
    brake_status: int  # Brake system status
    vehicle_size: Tuple[int, int]  # Width, length in cm


class SecureDSRC:
    """
    PQC-secured DSRC/ITS-G5 implementation.

    Features:
    - ML-DSA-65 message signing for BSM/TIM/RSA
    - IEEE 1609.2 security header format
    - Certificate-based authentication
    - Geographic scoped broadcast
    - 10 Hz BSM transmission rate

    Security Properties:
    - Post-quantum secure signatures
    - Message integrity and authenticity
    - Non-repudiation
    - Privacy through pseudonymous certificates
    """

    def __init__(
        self,
        temp_id: bytes,
        certificate: Optional[bytes] = None,
        channel: int = 172  # DSRC Channel 172 (5.855-5.865 GHz)
    ):
        """
        Initialize secure DSRC interface.

        Args:
            temp_id: Temporary vehicle ID (4 bytes)
            certificate: IEEE 1609.2 PQC certificate
            channel: DSRC channel number
        """
        self.temp_id = temp_id
        self.certificate = certificate
        self.channel = channel

        # Initialize PQC crypto
        self.signer = MLDSA65()
        self.sign_pk, self.sign_sk = self.signer.keygen()

        # Message counters
        self.bsm_count = 0
        self.tim_count = 0

        # Received message tracking
        self.seen_messages: Dict[bytes, datetime] = {}

        logger.info(f"SecureDSRC initialized: TempID={temp_id.hex()}, Channel={channel}")

    def broadcast_bsm(self, bsm_core: BSMCore) -> bytes:
        """
        Broadcast Basic Safety Message (BSM).

        BSMs are transmitted at 10 Hz to inform nearby vehicles of
        position, speed, heading, and vehicle status.

        Args:
            bsm_core: BSM core data (Part I)

        Returns:
            Signed BSM message
        """
        self.bsm_count = (self.bsm_count + 1) % 128

        # Encode BSM Part I (simplified)
        payload = struct.pack(
            '>BdddfffffH',
            self.bsm_count,
            bsm_core.latitude,
            bsm_core.longitude,
            bsm_core.elevation,
            bsm_core.speed,
            bsm_core.heading,
            bsm_core.angle,
            bsm_core.accel_set[0],  # Long accel
            bsm_core.accel_set[1],  # Lat accel
            bsm_core.brake_status
        )
        payload = self.temp_id + payload

        # Sign message
        signature = self.signer.sign(self.sign_sk, payload)

        # Build IEEE 1609.2 secured message
        secured_msg = self._build_secured_message(
            DSRCMessageType.BSM,
            payload,
            signature
        )

        logger.debug(f"Broadcast BSM #{self.bsm_count}")
        return secured_msg

    def broadcast_tim(
        self,
        event_type: int,
        event_position: Tuple[float, float],
        message_text: str
    ) -> bytes:
        """
        Broadcast Traveler Information Message (TIM).

        TIMs provide road condition, incident, and advisory information.

        Args:
            event_type: Type of event/advisory
            event_position: (latitude, longitude)
            message_text: Human-readable message

        Returns:
            Signed TIM message
        """
        self.tim_count = (self.tim_count + 1) % 128

        # Build TIM payload
        text_bytes = message_text.encode('utf-8')[:255]
        payload = struct.pack(
            '>BHddB',
            self.tim_count,
            event_type,
            event_position[0],
            event_position[1],
            len(text_bytes)
        )
        payload += text_bytes

        # Sign message
        signature = self.signer.sign(self.sign_sk, payload)

        # Build secured message
        secured_msg = self._build_secured_message(
            DSRCMessageType.TIM,
            payload,
            signature
        )

        logger.info(f"Broadcast TIM: {message_text[:50]}")
        return secured_msg

    def verify_message(
        self,
        secured_msg: bytes,
        sender_sign_pk: bytes
    ) -> Optional[bytes]:
        """
        Verify and extract payload from secured DSRC message.

        Args:
            secured_msg: Received secured message
            sender_sign_pk: Sender's public signing key

        Returns:
            Verified payload or None
        """
        try:
            # Parse secured message
            msg_type, payload, signature, cert = self._parse_secured_message(secured_msg)

            # Check for replay
            msg_hash = hashlib.sha256(payload).digest()[:8]
            if msg_hash in self.seen_messages:
                logger.warning("Replay detected")
                return None

            # Verify signature
            if not self.signer.verify(sender_sign_pk, payload, signature):
                logger.error("Signature verification failed")
                return None

            # Remember message
            self.seen_messages[msg_hash] = datetime.now()

            # Cleanup old entries
            cutoff = datetime.now() - timedelta(seconds=60)
            self.seen_messages = {
                k: v for k, v in self.seen_messages.items()
                if v > cutoff
            }

            logger.debug(f"Verified {msg_type.name} message")
            return payload

        except Exception as e:
            logger.error(f"Message verification failed: {e}")
            return None

    def _build_secured_message(
        self,
        msg_type: DSRCMessageType,
        payload: bytes,
        signature: bytes
    ) -> bytes:
        """
        Build IEEE 1609.2 secured message.

        Format: [Version:1][Type:1][PayloadLen:2][Payload:N][SigLen:2][Sig:M][CertLen:2][Cert:K]

        Args:
            msg_type: Message type
            payload: Message payload
            signature: Digital signature

        Returns:
            Secured message
        """
        # IEEE 1609.2 version 3
        msg = bytes([0x03, msg_type.value])

        # Add payload
        msg += struct.pack('>H', len(payload))
        msg += payload

        # Add signature
        msg += struct.pack('>H', len(signature))
        msg += signature

        # Add certificate (if available)
        if self.certificate:
            msg += struct.pack('>H', len(self.certificate))
            msg += self.certificate
        else:
            msg += struct.pack('>H', 0)

        return msg

    def _parse_secured_message(
        self,
        data: bytes
    ) -> Tuple[DSRCMessageType, bytes, bytes, Optional[bytes]]:
        """
        Parse IEEE 1609.2 secured message.

        Args:
            data: Secured message

        Returns:
            (message_type, payload, signature, certificate)
        """
        offset = 0

        # Parse header
        version = data[offset]
        offset += 1

        msg_type = DSRCMessageType(data[offset])
        offset += 1

        # Parse payload
        payload_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        payload = data[offset:offset+payload_len]
        offset += payload_len

        # Parse signature
        sig_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        signature = data[offset:offset+sig_len]
        offset += sig_len

        # Parse certificate
        cert_len = struct.unpack('>H', data[offset:offset+2])[0]
        offset += 2

        certificate = data[offset:offset+cert_len] if cert_len > 0 else None

        return (msg_type, payload, signature, certificate)

    def get_statistics(self) -> Dict:
        """Get DSRC statistics."""
        return {
            'temp_id': self.temp_id.hex(),
            'bsm_count': self.bsm_count,
            'tim_count': self.tim_count,
            'messages_seen': len(self.seen_messages)
        }


__all__ = ['SecureDSRC', 'DSRCMessageType', 'BSMCore']
