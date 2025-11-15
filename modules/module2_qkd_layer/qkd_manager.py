"""
QKD Manager - Manages QKD sessions and key lifecycle.

Integrates QKD protocols with automotive key management requirements:
- Automated key refresh
- Key rotation based on usage/time
- Integration with ECU and V2X systems
"""

import time
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum

from .bb84 import BB84Protocol, BB84KeyPair
from .e91 import E91Protocol, E91KeyPair


class QKDProtocolType(Enum):
    """Supported QKD protocols."""

    BB84 = "BB84"
    E91 = "E91"
    BBM92 = "BBM92"


@dataclass
class QKDSession:
    """QKD session information."""

    session_id: str
    protocol: QKDProtocolType
    alice_id: str
    bob_id: str
    shared_key: bytes
    created_at: float
    expires_at: float
    qber: Optional[float] = None

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return time.time() > self.expires_at


class QKDManager:
    """
    QKD Session Manager for automotive systems.

    Manages QKD sessions, key distribution, and key lifecycle.

    Example:
        >>> manager = QKDManager()
        >>> session = manager.create_session("ECU-1", "ECU-2", QKDProtocolType.BB84)
        >>> key = manager.get_key(session.session_id)
    """

    def __init__(self, default_key_lifetime_hours: int = 24):
        """
        Initialize QKD Manager.

        Args:
            default_key_lifetime_hours: Default key lifetime in hours
        """
        self.sessions: Dict[str, QKDSession] = {}
        self.default_key_lifetime_hours = default_key_lifetime_hours

    def create_session(
        self,
        alice_id: str,
        bob_id: str,
        protocol: QKDProtocolType = QKDProtocolType.BB84,
        num_qubits: int = 1000,
    ) -> QKDSession:
        """
        Create a new QKD session.

        Args:
            alice_id: Alice's identifier (e.g., ECU ID)
            bob_id: Bob's identifier
            protocol: QKD protocol to use
            num_qubits: Number of qubits for key generation

        Returns:
            QKDSession object
        """
        # Generate session ID
        import secrets
        session_id = secrets.token_hex(16)

        # Generate key using specified protocol
        if protocol == QKDProtocolType.BB84:
            bb84 = BB84Protocol(num_qubits=num_qubits)
            key_pair = bb84.generate_key_pair()
            shared_key = key_pair.alice_key
            qber = key_pair.qber
        elif protocol == QKDProtocolType.E91:
            e91 = E91Protocol(num_pairs=num_qubits)
            key_pair = e91.generate_key_pair()
            shared_key = key_pair.alice_key
            qber = None
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")

        # Create session
        current_time = time.time()
        session = QKDSession(
            session_id=session_id,
            protocol=protocol,
            alice_id=alice_id,
            bob_id=bob_id,
            shared_key=shared_key,
            created_at=current_time,
            expires_at=current_time + (self.default_key_lifetime_hours * 3600),
            qber=qber,
        )

        # Store session
        self.sessions[session_id] = session

        print(f"Created QKD session {session_id}")
        print(f"  Protocol: {protocol.value}")
        print(f"  Alice: {alice_id}, Bob: {bob_id}")
        print(f"  Key length: {len(shared_key)} bytes")
        if qber is not None:
            print(f"  QBER: {qber:.4f}")

        return session

    def get_key(self, session_id: str) -> bytes:
        """Get shared key for a session."""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        session = self.sessions[session_id]

        if session.is_expired():
            raise ValueError(f"Session expired: {session_id}")

        return session.shared_key

    def refresh_key(self, session_id: str, num_qubits: int = 1000) -> QKDSession:
        """Refresh key for an existing session."""
        if session_id not in self.sessions:
            raise ValueError(f"Session not found: {session_id}")

        old_session = self.sessions[session_id]

        # Create new session with same participants
        new_session = self.create_session(
            alice_id=old_session.alice_id,
            bob_id=old_session.bob_id,
            protocol=old_session.protocol,
            num_qubits=num_qubits,
        )

        # Remove old session
        del self.sessions[session_id]

        print(f"Refreshed session {session_id} -> {new_session.session_id}")

        return new_session

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions."""
        expired = [
            sid for sid, session in self.sessions.items()
            if session.is_expired()
        ]

        for sid in expired:
            del self.sessions[sid]

        print(f"Cleaned up {len(expired)} expired sessions")
        return len(expired)
