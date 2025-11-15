"""
Unit tests for Module 1: PQC Layer
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module1_pqc_layer import MLKEM768, MLDSA65, SLHDSA128s


class TestMLKEM:
    """Test ML-KEM implementation."""

    def test_keygen(self):
        """Test key generation."""
        kem = MLKEM768()
        keypair = kem.generate_keypair()

        assert keypair is not None
        assert len(keypair.public_key) > 0
        assert len(keypair.secret_key) > 0
        assert keypair.algorithm == "ML-KEM-768"

    def test_encaps_decaps(self):
        """Test encapsulation and decapsulation."""
        kem = MLKEM768()
        keypair = kem.generate_keypair()

        # Encapsulate
        ciphertext, shared_secret_sender = kem.encapsulate(keypair.public_key)

        # Decapsulate
        shared_secret_receiver = kem.decapsulate(keypair.secret_key, ciphertext)

        # Verify shared secrets match
        assert shared_secret_sender == shared_secret_receiver


class TestMLDSA:
    """Test ML-DSA implementation."""

    def test_keygen(self):
        """Test key generation."""
        dsa = MLDSA65()
        keypair = dsa.generate_keypair()

        assert keypair is not None
        assert len(keypair.public_key) > 0
        assert len(keypair.secret_key) > 0

    def test_sign_verify(self):
        """Test signing and verification."""
        dsa = MLDSA65()
        keypair = dsa.generate_keypair()
        message = b"Test message"

        # Sign
        signature = dsa.sign(keypair.secret_key, message)

        # Verify
        is_valid = dsa.verify(keypair.public_key, message, signature)
        assert is_valid

    def test_tamper_detection(self):
        """Test tampering detection."""
        dsa = MLDSA65()
        keypair = dsa.generate_keypair()
        message = b"Original message"
        tampered = b"Tampered message"

        # Sign original
        signature = dsa.sign(keypair.secret_key, message)

        # Verify with tampered message should fail
        is_valid = dsa.verify(keypair.public_key, tampered, signature)
        assert not is_valid


class TestSLHDSA:
    """Test SLH-DSA implementation."""

    def test_keygen(self):
        """Test key generation."""
        sig = SLHDSA128s()
        keypair = sig.generate_keypair()

        assert keypair is not None
        assert len(keypair.public_key) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
