"""
Unit tests for Module 2: QKD Layer
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module2_qkd_layer import BB84Protocol, QKDManager, QKDProtocolType


class TestBB84:
    """Test BB84 protocol."""

    def test_key_generation(self):
        """Test BB84 key generation."""
        bb84 = BB84Protocol(num_qubits=100)
        key_pair = bb84.generate_key_pair()

        assert key_pair is not None
        assert key_pair.final_key_length > 0
        assert 0 <= key_pair.qber <= 1.0

    def test_key_agreement(self):
        """Test that Alice and Bob get same key."""
        bb84 = BB84Protocol(num_qubits=100)
        key_pair = bb84.generate_key_pair()

        # In BB84, Alice and Bob should have identical keys
        assert key_pair.alice_key == key_pair.bob_key


class TestQKDManager:
    """Test QKD Manager."""

    def test_create_session(self):
        """Test session creation."""
        manager = QKDManager()
        session = manager.create_session(
            "ECU-1", "ECU-2", QKDProtocolType.BB84, num_qubits=100
        )

        assert session is not None
        assert session.shared_key is not None
        assert len(session.shared_key) > 0

    def test_get_key(self):
        """Test key retrieval."""
        manager = QKDManager()
        session = manager.create_session(
            "ECU-1", "ECU-2", QKDProtocolType.BB84, num_qubits=100
        )

        key = manager.get_key(session.session_id)
        assert key == session.shared_key


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
