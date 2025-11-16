"""
Unit tests for Module 4: CAN Security

Tests the secure CAN bus implementation with PQC key exchange,
authentication, and encryption.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module4_invehicle_comm.can_security import (
    SecureCANBus,
    CANSecureFrame,
    CANSecurityLevel,
    setup_ecu_can_network
)


class TestCANSecureFrame:
    """Test CAN secure frame serialization/deserialization."""

    def test_frame_serialization(self):
        """Test frame can be serialized and deserialized."""
        frame = CANSecureFrame(
            can_id=0x100,
            sequence_number=42,
            mac=b'\x11\x22\x33\x44\x55\x66\x77\x88',
            payload=b'test data',
            is_encrypted=True,
            timestamp=1234567890.0
        )

        # Serialize
        data = frame.to_bytes()
        assert len(data) > 0

        # Deserialize
        frame2 = CANSecureFrame.from_bytes(0x100, data)
        assert frame2.sequence_number == frame.sequence_number
        assert frame2.payload == frame.payload

    def test_frame_too_short(self):
        """Test error handling for too-short frames."""
        with pytest.raises(ValueError, match="too short"):
            CANSecureFrame.from_bytes(0x100, b'\x00\x01')


class TestSecureCANBus:
    """Test secure CAN bus implementation."""

    def test_ecu_initialization(self):
        """Test ECU initialization."""
        ecu = SecureCANBus(
            can_id=0x100,
            node_name="Test_ECU",
            security_level=CANSecurityLevel.AUTH_ENCRYPT
        )

        assert ecu.can_id == 0x100
        assert ecu.node_name == "Test_ECU"
        assert ecu.security_level == CANSecurityLevel.AUTH_ENCRYPT
        assert len(ecu.get_public_key()) > 0

    def test_invalid_can_id(self):
        """Test validation of CAN ID."""
        with pytest.raises(ValueError, match="CAN ID must be"):
            SecureCANBus(can_id=-1)

        with pytest.raises(ValueError, match="CAN ID must be"):
            SecureCANBus(can_id=0x20000000)

    def test_key_exchange(self):
        """Test ML-KEM key exchange between two ECUs."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        # Exchange public keys and establish sessions
        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Check sessions are established
        assert 0x200 in ecu1.session_keys
        assert 0x100 in ecu2.session_keys

    def test_secure_messaging(self):
        """Test secure message exchange."""
        # Setup two ECUs
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        # Establish sessions
        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Send secure message from ECU1 to ECU2
        message = b"Engine RPM: 3000"
        frame = ecu1.send_secure_frame(message, 0x200)

        # Receive and decrypt on ECU2
        received_payload = ecu2.receive_secure_frame(frame)

        # Verify message was received correctly
        assert received_payload == message

    def test_authentication_only(self):
        """Test authentication-only mode (no encryption)."""
        ecu1 = SecureCANBus(
            can_id=0x100,
            node_name="ECU1",
            security_level=CANSecurityLevel.AUTH_ONLY
        )
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        message = b"Test message"
        frame = ecu1.send_secure_frame(message, 0x200, CANSecurityLevel.AUTH_ONLY)

        received = ecu2.receive_secure_frame(frame)
        assert received == message

    def test_replay_attack_detection(self):
        """Test detection of replay attacks."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Send first message
        frame1 = ecu1.send_secure_frame(b"Message 1", 0x200)
        ecu2.receive_secure_frame(frame1)

        # Send second message
        frame2 = ecu1.send_secure_frame(b"Message 2", 0x200)
        ecu2.receive_secure_frame(frame2)

        # Try to replay first message (should fail)
        with pytest.raises(ValueError, match="Replay attack detected"):
            ecu2.receive_secure_frame(frame1)

    def test_mac_verification_failure(self):
        """Test MAC verification failure detection."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Send message
        frame = ecu1.send_secure_frame(b"Original message", 0x200)

        # Tamper with MAC
        tampered_frame = CANSecureFrame(
            can_id=frame.can_id,
            sequence_number=frame.sequence_number,
            mac=b'\x00' * len(frame.mac),  # Invalid MAC
            payload=frame.payload,
            is_encrypted=frame.is_encrypted,
            timestamp=frame.timestamp
        )

        # Verification should fail
        with pytest.raises(ValueError, match="MAC verification failed"):
            ecu2.receive_secure_frame(tampered_frame)

    def test_payload_size_limit(self):
        """Test payload size validation."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1", use_can_fd=False)
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        ecu1.establish_session(0x200, ecu2.get_public_key())

        # Try to send payload that's too large
        large_payload = b"X" * 100
        with pytest.raises(ValueError, match="Payload too large"):
            ecu1.send_secure_frame(large_payload, 0x200)

    def test_no_session_error(self):
        """Test error when trying to send without established session."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")

        with pytest.raises(ValueError, match="No session established"):
            ecu1.send_secure_frame(b"test", 0x200)

    def test_statistics(self):
        """Test statistics reporting."""
        ecu1 = SecureCANBus(can_id=0x100, node_name="ECU1")
        ecu2 = SecureCANBus(can_id=0x200, node_name="ECU2")

        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Send some messages
        for i in range(5):
            frame = ecu1.send_secure_frame(f"Message {i}".encode(), 0x200)
            ecu2.receive_secure_frame(frame)

        # Check statistics
        stats1 = ecu1.get_statistics()
        assert stats1["node_name"] == "ECU1"
        assert stats1["total_tx_messages"] == 5
        assert stats1["active_sessions"] == 1

        stats2 = ecu2.get_statistics()
        assert stats2["total_rx_messages"] == 5

    def test_can_fd_vs_standard(self):
        """Test CAN-FD vs standard CAN differences."""
        ecu_fd = SecureCANBus(can_id=0x100, use_can_fd=True)
        ecu_std = SecureCANBus(can_id=0x200, use_can_fd=False)

        assert ecu_fd.max_payload == 48
        assert ecu_std.max_payload == 2

    def test_constant_time_compare(self):
        """Test constant-time comparison."""
        ecu = SecureCANBus(can_id=0x100)

        # Same values should return True
        assert ecu._constant_time_compare(b"test", b"test")

        # Different values should return False
        assert not ecu._constant_time_compare(b"test", b"fake")

        # Different lengths should return False
        assert not ecu._constant_time_compare(b"short", b"longer string")


class TestCANNetwork:
    """Test multi-ECU CAN network setup."""

    def test_network_setup(self):
        """Test automatic network setup with multiple ECUs."""
        ecu_configs = [
            {"can_id": 0x100, "node_name": "Engine_ECU"},
            {"can_id": 0x200, "node_name": "Brake_ECU"},
            {"can_id": 0x300, "node_name": "Gateway_ECU"}
        ]

        ecus = setup_ecu_can_network(ecu_configs)

        # Check all ECUs were created
        assert len(ecus) == 3
        assert 0x100 in ecus
        assert 0x200 in ecus
        assert 0x300 in ecus

        # Check sessions are established between all pairs
        assert 0x200 in ecus[0x100].session_keys
        assert 0x300 in ecus[0x100].session_keys
        assert 0x100 in ecus[0x200].session_keys
        assert 0x300 in ecus[0x200].session_keys

    def test_network_messaging(self):
        """Test messaging across a network of ECUs."""
        ecu_configs = [
            {"can_id": 0x100, "node_name": "ECU1"},
            {"can_id": 0x200, "node_name": "ECU2"},
            {"can_id": 0x300, "node_name": "ECU3"}
        ]

        ecus = setup_ecu_can_network(ecu_configs)

        # ECU1 -> ECU2
        msg1 = b"ECU1 to ECU2"
        frame1 = ecus[0x100].send_secure_frame(msg1, 0x200)
        received1 = ecus[0x200].receive_secure_frame(frame1)
        assert received1 == msg1

        # ECU2 -> ECU3
        msg2 = b"ECU2 to ECU3"
        frame2 = ecus[0x200].send_secure_frame(msg2, 0x300)
        received2 = ecus[0x300].receive_secure_frame(frame2)
        assert received2 == msg2

        # ECU3 -> ECU1
        msg3 = b"ECU3 to ECU1"
        frame3 = ecus[0x300].send_secure_frame(msg3, 0x100)
        received3 = ecus[0x100].receive_secure_frame(frame3)
        assert received3 == msg3


class TestKeyRotation:
    """Test key rotation mechanisms."""

    def test_key_rotation_threshold(self):
        """Test key rotation is triggered by message threshold."""
        ecu1 = SecureCANBus(can_id=0x100)
        ecu2 = SecureCANBus(can_id=0x200)

        ecu1.establish_session(0x200, ecu2.get_public_key())
        ecu2.establish_session(0x100, ecu1.get_public_key())

        # Set low threshold for testing
        ecu1.key_rotation_threshold = 10

        # Send messages up to threshold
        for i in range(10):
            assert not ecu1._check_key_rotation(0x200)
            frame = ecu1.send_secure_frame(f"Message {i}".encode(), 0x200)
            ecu2.receive_secure_frame(frame)

        # Next check should indicate rotation needed
        assert ecu1._check_key_rotation(0x200)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
