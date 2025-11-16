"""
Unit tests for Secure Memory Management

Tests secure key zeroization and memory protection functionality.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module1_pqc_layer.secure_memory import (
    SecureBytes,
    SecureKeyPair,
    secure_compare,
    secure_random_bytes,
    secure_operation,
    zeroize_bytes,
    create_secure_keypair
)


class TestSecureBytes:
    """Test SecureBytes implementation."""

    def test_basic_usage(self):
        """Test basic SecureBytes usage."""
        data = b"secret data"
        secure = SecureBytes(data)

        assert len(secure) == len(data)
        assert secure.data == bytearray(data)
        assert not secure.is_zeroized

    def test_context_manager(self):
        """Test SecureBytes as context manager."""
        data = b"secret key"

        with SecureBytes(data) as secure:
            # Data should be accessible
            assert secure.data == bytearray(data)
            assert not secure.is_zeroized

        # After exit, data should be zeroized
        assert secure.is_zeroized

        # Accessing zeroized data should raise error
        with pytest.raises(ValueError, match="zeroized"):
            _ = secure.data

    def test_manual_zeroization(self):
        """Test manual zeroization."""
        secure = SecureBytes(b"sensitive data")
        assert not secure.is_zeroized

        # Manually zeroize
        secure.zeroize()
        assert secure.is_zeroized

        # Double zeroize should be safe
        secure.zeroize()
        assert secure.is_zeroized

    def test_zeroization_overwrites(self):
        """Test that zeroization actually overwrites data."""
        data = bytearray(b"secret key material")
        secure = SecureBytes(data)

        # Get reference to internal data
        internal_data = secure._data

        # Zeroize
        secure.zeroize()

        # Check that internal data is all zeros
        assert all(byte == 0x00 for byte in internal_data)

    def test_bytearray_input(self):
        """Test SecureBytes with bytearray input."""
        data = bytearray(b"test data")
        secure = SecureBytes(data)

        assert secure.data == data
        assert secure.data is not data  # Should be a copy

    def test_invalid_input(self):
        """Test SecureBytes rejects invalid input."""
        with pytest.raises(TypeError, match="must be bytes or bytearray"):
            SecureBytes("string")

        with pytest.raises(TypeError, match="must be bytes or bytearray"):
            SecureBytes(123)

    def test_repr(self):
        """Test string representation."""
        secure = SecureBytes(b"test")
        repr_str = repr(secure)
        assert "SecureBytes" in repr_str
        assert "4" in repr_str  # length

        secure.zeroize()
        repr_str = repr(secure)
        assert "zeroized" in repr_str


class TestSecureKeyPair:
    """Test SecureKeyPair implementation."""

    def test_basic_usage(self):
        """Test basic SecureKeyPair usage."""
        public = b"public key data"
        secret = b"secret key data"

        keypair = SecureKeyPair(public, secret)

        assert keypair.public_key == public
        assert keypair.secret_key == bytearray(secret)
        assert not keypair.is_zeroized

    def test_context_manager(self):
        """Test SecureKeyPair as context manager."""
        with SecureKeyPair(b"public", b"secret") as keypair:
            assert not keypair.is_zeroized
            _ = keypair.secret_key

        # After exit, secret key should be zeroized
        assert keypair.is_zeroized

    def test_public_key_unaffected(self):
        """Test that public key is not zeroized."""
        public = b"public key"
        secret = b"secret key"

        keypair = SecureKeyPair(public, secret)
        keypair.zeroize()

        # Public key should still be accessible
        assert keypair.public_key == public

        # Secret key should be zeroized
        assert keypair.is_zeroized

    def test_destructor(self):
        """Test automatic zeroization on deletion."""
        keypair = SecureKeyPair(b"public", b"secret")
        secret_data = keypair._secret_key._data

        # Delete keypair
        del keypair

        # Secret data should be zeroized
        assert all(byte == 0x00 for byte in secret_data)


class TestSecureCompare:
    """Test constant-time comparison."""

    def test_equal_values(self):
        """Test comparison of equal values."""
        assert secure_compare(b"test", b"test")
        assert secure_compare(b"", b"")
        assert secure_compare(b"long string here", b"long string here")

    def test_unequal_values(self):
        """Test comparison of unequal values."""
        assert not secure_compare(b"test", b"fake")
        assert not secure_compare(b"a", b"b")
        assert not secure_compare(b"similar", b"similar!")

    def test_different_lengths(self):
        """Test comparison of different length values."""
        assert not secure_compare(b"short", b"longer string")
        assert not secure_compare(b"", b"nonempty")


class TestSecureRandomBytes:
    """Test secure random byte generation."""

    def test_generation(self):
        """Test random byte generation."""
        with secure_random_bytes(32) as random:
            assert len(random) == 32
            assert not random.is_zeroized

        # Should be zeroized after context exit
        assert random.is_zeroized

    def test_different_values(self):
        """Test that generated values are different."""
        with secure_random_bytes(32) as rand1:
            data1 = bytes(rand1.data)

        with secure_random_bytes(32) as rand2:
            data2 = bytes(rand2.data)

        # Should be extremely unlikely to be equal
        assert data1 != data2


class TestSecureOperation:
    """Test secure operation context manager."""

    def test_context_manager(self):
        """Test secure_operation context manager."""
        data = b"sensitive data"

        with secure_operation(data) as secure:
            assert secure.data == bytearray(data)
            assert not secure.is_zeroized

        # Should be zeroized after exit
        assert secure.is_zeroized

    def test_exception_handling(self):
        """Test that zeroization happens even with exceptions."""
        data = b"sensitive data"
        secure_ref = None

        try:
            with secure_operation(data) as secure:
                secure_ref = secure
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Should still be zeroized
        assert secure_ref.is_zeroized


class TestZeroizeBytes:
    """Test direct byte array zeroization."""

    def test_bytearray_zeroization(self):
        """Test zeroization of bytearray."""
        data = bytearray(b"secret data here")
        original_length = len(data)

        zeroize_bytes(data)

        # All bytes should be zero
        assert len(data) == original_length
        assert all(byte == 0x00 for byte in data)

    def test_memoryview_zeroization(self):
        """Test zeroization of memoryview."""
        base_data = bytearray(b"secret data")
        view = memoryview(base_data)

        zeroize_bytes(view)

        # Base data should be zeroized
        assert all(byte == 0x00 for byte in base_data)

    def test_immutable_bytes_error(self):
        """Test that immutable bytes raises error."""
        with pytest.raises(TypeError, match="mutable byte sequences"):
            zeroize_bytes(b"immutable bytes")

    def test_invalid_type_error(self):
        """Test that invalid types raise error."""
        with pytest.raises(TypeError, match="mutable byte sequences"):
            zeroize_bytes("string")

        with pytest.raises(TypeError, match="mutable byte sequences"):
            zeroize_bytes(123)


class TestCreateSecureKeyPair:
    """Test secure keypair creation helper."""

    def test_creation(self):
        """Test keypair creation."""
        public = b"public key"
        secret = b"secret key"

        with create_secure_keypair(public, secret) as keypair:
            assert keypair.public_key == public
            assert keypair.secret_key == bytearray(secret)

        # Secret should be zeroized
        assert keypair.is_zeroized


class TestMemoryLocking:
    """Test memory locking (platform-dependent)."""

    def test_memory_lock_attempt(self):
        """Test that memory locking is attempted (may or may not succeed)."""
        # This test just verifies the code path executes without error
        # Actual locking success depends on platform and permissions
        secure = SecureBytes(b"test data")

        # Should have a _locked attribute
        assert hasattr(secure, '_locked')

        # Value depends on platform and permissions
        assert isinstance(secure._locked, bool)

        secure.zeroize()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
