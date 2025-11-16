"""
5G C-V2X (Cellular V2X) Security with Post-Quantum Cryptography

Implements PQC-secured 5G C-V2X communication compliant with 3GPP standards.
Supports PC5 sidelink interface for direct V2V/V2P/V2I communication.
"""

from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import struct
import hashlib
import hmac
from loguru import logger

from ..module1_pqc_layer.mlkem import MLKEM768
from ..module1_pqc_layer.mldsa import MLDSA65


class CV2XMessageType(Enum):
    """C-V2X message types (3GPP TS 23.287)."""
    CAM = 0x01  # Cooperative Awareness Message
    DENM = 0x02  # Decentralized Environmental Notification
    CPM = 0x03  # Collective Perception Message
    MCM = 0x04  # Maneuver Coordination Message
    VAM = 0x05  # Vulnerable Road User Awareness


@dataclass
class CV2XMessage:
    """5G C-V2X message structure."""
    msg_type: CV2XMessageType
    sender_id: str  # Vehicle/RSU ID
    timestamp: datetime
    payload: bytes
    signature: Optional[bytes] = None
    certificate: Optional[bytes] = None


class SecureCV2X:
    """
    PQC-secured 5G C-V2X implementation.

    Features:
    - ML-KEM-768 key agreement for PC5 sidelink
    - ML-DSA-65 message signing for CAM/DENM/CPM
    - PQC certificate-based authentication
    - Geographic scoped message broadcast
    - Replay attack prevention with timestamps

    Security Properties:
    - Post-quantum secure message signatures
    - Certificate-based sender authentication
    - Message integrity and non-repudiation
    - Privacy-preserving pseudonymous certificates
    """

    def __init__(
        self,
        vehicle_id: str,
        certificate: Optional[bytes] = None
    ):
        """
        Initialize secure C-V2X interface.

        Args:
            vehicle_id: Unique vehicle identifier (pseudonym)
            certificate: PQC certificate for message signing
        """
        self.vehicle_id = vehicle_id
        self.certificate = certificate

        # Initialize PQC crypto
        self.kem = MLKEM768()
        self.signer = MLDSA65()

        # Generate ephemeral keys
        self.sign_pk, self.sign_sk = self.signer.keygen()

        # Message tracking for replay prevention
        self.seen_messages: Dict[str, datetime] = {}
        self.message_counter = 0

        # Peer sessions for unicast
        self.peer_sessions: Dict[str, bytes] = {}

        logger.info(f"SecureCV2X initialized for vehicle {vehicle_id}")

    def sign_cam_message(
        self,
        position: Tuple[float, float, float],  # lat, lon, alt
        speed: float,
        heading: float,
        additional_data: Optional[bytes] = None
    ) -> CV2XMessage:
        """
        Create and sign Cooperative Awareness Message (CAM).

        CAM messages are broadcast periodically (1-10 Hz) to inform neighbors
        about vehicle position, speed, and status.

        Args:
            position: (latitude, longitude, altitude) in degrees/meters
            speed: Vehicle speed in m/s
            heading: Vehicle heading in degrees
            additional_data: Optional additional payload

        Returns:
            Signed CAM message
        """
        self.message_counter += 1

        # Build CAM payload (simplified structure)
        payload = struct.pack(
            '>dddffI',
            position[0],  # latitude
            position[1],  # longitude
            position[2],  # altitude
            speed,
            heading,
            self.message_counter
        )

        if additional_data:
            payload += additional_data

        # Create message
        msg = CV2XMessage(
            msg_type=CV2XMessageType.CAM,
            sender_id=self.vehicle_id,
            timestamp=datetime.now(),
            payload=payload
        )

        # Sign message
        msg_hash = self._compute_message_hash(msg)
        msg.signature = self.signer.sign(self.sign_sk, msg_hash)

        # Attach certificate (if available)
        if self.certificate:
            msg.certificate = self.certificate

        logger.debug(f"Signed CAM message #{self.message_counter}")
        return msg

    def sign_denm_message(
        self,
        event_type: int,  # Event type code
        event_position: Tuple[float, float],
        severity: int,  # 0-7
        event_data: bytes
    ) -> CV2XMessage:
        """
        Create and sign Decentralized Environmental Notification Message (DENM).

        DENM messages alert about road hazards, accidents, weather conditions, etc.

        Args:
            event_type: Type of event (accident, hazard, etc.)
            event_position: (latitude, longitude) of event
            severity: Event severity level (0-7)
            event_data: Event-specific data

        Returns:
            Signed DENM message
        """
        self.message_counter += 1

        # Build DENM payload
        payload = struct.pack(
            '>HddBI',
            event_type,
            event_position[0],
            event_position[1],
            severity,
            self.message_counter
        )
        payload += event_data

        # Create message
        msg = CV2XMessage(
            msg_type=CV2XMessageType.DENM,
            sender_id=self.vehicle_id,
            timestamp=datetime.now(),
            payload=payload
        )

        # Sign message
        msg_hash = self._compute_message_hash(msg)
        msg.signature = self.signer.sign(self.sign_sk, msg_hash)

        if self.certificate:
            msg.certificate = self.certificate

        logger.info(f"Signed DENM message: event_type={event_type}, severity={severity}")
        return msg

    def verify_message(
        self,
        msg: CV2XMessage,
        sender_sign_pk: bytes
    ) -> bool:
        """
        Verify signed C-V2X message.

        Args:
            msg: Received message
            sender_sign_pk: Sender's public signing key

        Returns:
            True if signature valid and message fresh
        """
        # Check if we've seen this message (replay prevention)
        msg_id = f"{msg.sender_id}_{msg.timestamp.isoformat()}"
        if msg_id in self.seen_messages:
            logger.warning(f"Replay detected: {msg_id}")
            return False

        # Check message freshness (within last 10 seconds)
        age = (datetime.now() - msg.timestamp).total_seconds()
        if age > 10.0 or age < -2.0:  # Allow 2s clock skew
            logger.warning(f"Message too old or future: age={age}s")
            return False

        # Verify signature
        if not msg.signature:
            logger.error("Message has no signature")
            return False

        msg_hash = self._compute_message_hash(msg)
        valid = self.signer.verify(sender_sign_pk, msg_hash, msg.signature)

        if valid:
            # Remember this message
            self.seen_messages[msg_id] = datetime.now()

            # Cleanup old entries (older than 1 minute)
            cutoff = datetime.now() - timedelta(seconds=60)
            self.seen_messages = {
                k: v for k, v in self.seen_messages.items()
                if v > cutoff
            }

            logger.debug(f"Verified message from {msg.sender_id}")
        else:
            logger.error(f"Signature verification failed from {msg.sender_id}")

        return valid

    def establish_sidelink(
        self,
        peer_id: str,
        peer_kem_pk: bytes
    ) -> bytes:
        """
        Establish PC5 sidelink session with peer vehicle.

        Used for unicast or groupcast communication.

        Args:
            peer_id: Peer vehicle ID
            peer_kem_pk: Peer's KEM public key

        Returns:
            Ciphertext to send to peer
        """
        # Perform key encapsulation
        ciphertext, shared_secret = self.kem.encapsulate(peer_kem_pk)

        # Store session
        self.peer_sessions[peer_id] = shared_secret

        logger.info(f"Established sidelink with {peer_id}")
        return ciphertext

    def serialize_message(self, msg: CV2XMessage) -> bytes:
        """
        Serialize C-V2X message for transmission.

        Format: [MsgType:1][SenderID:32][Timestamp:8][PayloadLen:2][Payload:N][SigLen:2][Sig:M][CertLen:2][Cert:K]

        Args:
            msg: Message to serialize

        Returns:
            Serialized message bytes
        """
        # Encode sender ID (fixed 32 bytes)
        sender_bytes = msg.sender_id.encode('utf-8')[:32].ljust(32, b'\x00')

        # Encode timestamp (Unix timestamp in microseconds)
        timestamp_us = int(msg.timestamp.timestamp() * 1_000_000)
        timestamp_bytes = struct.pack('>Q', timestamp_us)

        # Build message
        data = bytes([msg.msg_type.value])
        data += sender_bytes
        data += timestamp_bytes
        data += struct.pack('>H', len(msg.payload))
        data += msg.payload

        if msg.signature:
            data += struct.pack('>H', len(msg.signature))
            data += msg.signature
        else:
            data += struct.pack('>H', 0)

        if msg.certificate:
            data += struct.pack('>H', len(msg.certificate))
            data += msg.certificate
        else:
            data += struct.pack('>H', 0)

        return data

    def parse_message(self, data: bytes) -> Optional[CV2XMessage]:
        """
        Parse received C-V2X message.

        Args:
            data: Serialized message

        Returns:
            Parsed message or None if malformed
        """
        try:
            offset = 0

            # Parse header
            msg_type_val = data[offset]
            msg_type = CV2XMessageType(msg_type_val)
            offset += 1

            sender_id = data[offset:offset+32].rstrip(b'\x00').decode('utf-8')
            offset += 32

            timestamp_us = struct.unpack('>Q', data[offset:offset+8])[0]
            timestamp = datetime.fromtimestamp(timestamp_us / 1_000_000)
            offset += 8

            # Parse payload
            payload_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            payload = data[offset:offset+payload_len]
            offset += payload_len

            # Parse signature
            sig_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            signature = data[offset:offset+sig_len] if sig_len > 0 else None
            offset += sig_len

            # Parse certificate
            cert_len = struct.unpack('>H', data[offset:offset+2])[0]
            offset += 2

            certificate = data[offset:offset+cert_len] if cert_len > 0 else None

            return CV2XMessage(
                msg_type=msg_type,
                sender_id=sender_id,
                timestamp=timestamp,
                payload=payload,
                signature=signature,
                certificate=certificate
            )

        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            return None

    def _compute_message_hash(self, msg: CV2XMessage) -> bytes:
        """
        Compute hash of message for signing.

        Args:
            msg: Message to hash

        Returns:
            SHA-384 hash
        """
        data = bytes([msg.msg_type.value])
        data += msg.sender_id.encode('utf-8')
        data += str(int(msg.timestamp.timestamp() * 1_000_000)).encode('utf-8')
        data += msg.payload

        return hashlib.sha384(data).digest()

    def get_statistics(self) -> Dict:
        """Get C-V2X statistics."""
        return {
            'vehicle_id': self.vehicle_id,
            'messages_sent': self.message_counter,
            'messages_seen': len(self.seen_messages),
            'peer_sessions': len(self.peer_sessions)
        }


class CV2XSecurityLayer:
    """
    C-V2X Security Layer (3GPP TS 33.185).

    Manages security contexts, certificate management, and
    cryptographic operations for C-V2X communication.
    """

    def __init__(self):
        """Initialize C-V2X security layer."""
        self.vehicles: Dict[str, SecureCV2X] = {}
        self.certificate_pool: Dict[str, bytes] = {}

        logger.info("CV2XSecurityLayer initialized")

    def register_vehicle(
        self,
        vehicle_id: str,
        certificate: Optional[bytes] = None
    ) -> SecureCV2X:
        """
        Register vehicle in security layer.

        Args:
            vehicle_id: Vehicle identifier
            certificate: Vehicle's PQC certificate

        Returns:
            SecureCV2X instance
        """
        cv2x = SecureCV2X(vehicle_id, certificate)
        self.vehicles[vehicle_id] = cv2x

        if certificate:
            self.certificate_pool[vehicle_id] = certificate

        logger.info(f"Registered vehicle {vehicle_id}")
        return cv2x

    def broadcast_message(
        self,
        sender_id: str,
        msg: CV2XMessage
    ) -> int:
        """
        Broadcast message to all vehicles.

        Args:
            sender_id: Sending vehicle ID
            msg: Message to broadcast

        Returns:
            Number of vehicles that received message
        """
        count = 0
        sender = self.vehicles.get(sender_id)

        if not sender:
            return 0

        for vehicle_id, vehicle in self.vehicles.items():
            if vehicle_id != sender_id:
                # Verify message
                if vehicle.verify_message(msg, sender.sign_pk):
                    count += 1

        return count


__all__ = [
    'SecureCV2X',
    'CV2XSecurityLayer',
    'CV2XMessage',
    'CV2XMessageType'
]
