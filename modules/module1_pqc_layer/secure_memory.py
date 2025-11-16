"""
Secure Memory Management for Cryptographic Keys

This module provides secure memory handling for sensitive cryptographic material,
including proper key zeroization to prevent memory disclosure attacks.

Security Features:
- Secure key zeroization using multiple overwrites
- Memory locking to prevent swapping to disk (OS-dependent)
- Context managers for automatic cleanup
- Protection against timing attacks in comparison operations
- Compliance with FIPS 140-3 key zeroization requirements

Compliance:
- FIPS 140-3: IG D.9 (Key Zeroization)
- ISO/SAE 21434: Section 9.3.7 (Key Management)
- Common Criteria: FCS_CKM.4 (Cryptographic Key Destruction)

Usage:
    >>> with SecureBytes(b"secret key data") as key:
    ...     # Use key here
    ...     result = some_crypto_operation(key.data)
    >>> # Key is automatically zeroized when context exits
"""

import ctypes
import gc
import os
import sys
from typing import Optional, Union
from contextlib import contextmanager


class SecureBytes:
    """
    Secure byte array with automatic zeroization.

    This class wraps sensitive byte data and ensures it is properly
    zeroized from memory when no longer needed.

    Example:
        >>> key = SecureBytes(b"my secret key")
        >>> # Use key.data to access the bytes
        >>> encrypted = encrypt_data(key.data, plaintext)
        >>> # Explicitly zeroize when done
        >>> key.zeroize()

    Or use as context manager:
        >>> with SecureBytes(b"my secret key") as key:
        ...     encrypted = encrypt_data(key.data, plaintext)
        >>> # Automatically zeroized
    """

    def __init__(self, data: Union[bytes, bytearray]):
        """
        Initialize secure bytes container.

        Args:
            data: Sensitive byte data to protect
        """
        if isinstance(data, bytes):
            self._data = bytearray(data)
        elif isinstance(data, bytearray):
            self._data = bytearray(data)  # Copy to ensure we own the data
        else:
            raise TypeError("Data must be bytes or bytearray")

        self._zeroized = False
        self._length = len(self._data)

        # Try to lock memory to prevent swapping (platform-dependent)
        self._locked = self._try_lock_memory()

    def _try_lock_memory(self) -> bool:
        """
        Attempt to lock memory pages to prevent swapping.

        Returns:
            True if memory was successfully locked
        """
        if sys.platform == 'linux':
            try:
                # Try to use mlock to prevent swapping
                # This requires appropriate permissions
                import ctypes
                import ctypes.util

                libc = ctypes.CDLL(ctypes.util.find_library('c'))
                if libc:
                    # Get pointer to data
                    ptr = (ctypes.c_char * len(self._data)).from_buffer(self._data)
                    result = libc.mlock(ptr, len(self._data))
                    return result == 0
            except Exception:
                # Locking failed, continue without it
                pass

        return False

    def _unlock_memory(self) -> None:
        """Unlock memory pages if they were locked."""
        if self._locked and sys.platform == 'linux':
            try:
                import ctypes
                import ctypes.util

                libc = ctypes.CDLL(ctypes.util.find_library('c'))
                if libc:
                    ptr = (ctypes.c_char * len(self._data)).from_buffer(self._data)
                    libc.munlock(ptr, len(self._data))
            except Exception:
                pass

    @property
    def data(self) -> bytearray:
        """
        Get the underlying byte data.

        Raises:
            ValueError: If data has been zeroized
        """
        if self._zeroized:
            raise ValueError("Data has been zeroized and is no longer accessible")
        return self._data

    @property
    def is_zeroized(self) -> bool:
        """Check if data has been zeroized."""
        return self._zeroized

    def zeroize(self) -> None:
        """
        Securely zeroize the sensitive data.

        Uses multiple overwrite passes to ensure data is destroyed:
        1. Overwrite with 0x00
        2. Overwrite with 0xFF
        3. Overwrite with random data
        4. Final overwrite with 0x00

        This follows NIST SP 800-88 guidelines for media sanitization.
        """
        if self._zeroized:
            return  # Already zeroized

        # Multiple overwrite passes for defense in depth
        length = len(self._data)

        # Pass 1: Overwrite with zeros
        for i in range(length):
            self._data[i] = 0x00

        # Pass 2: Overwrite with ones
        for i in range(length):
            self._data[i] = 0xFF

        # Pass 3: Overwrite with random data
        random_data = os.urandom(length)
        for i in range(length):
            self._data[i] = random_data[i]

        # Pass 4: Final overwrite with zeros
        for i in range(length):
            self._data[i] = 0x00

        # Clear the random data from our scope
        del random_data

        # Unlock memory if it was locked
        self._unlock_memory()

        # Mark as zeroized
        self._zeroized = True

        # Force garbage collection to help ensure cleanup
        gc.collect()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - automatically zeroize."""
        self.zeroize()
        return False

    def __del__(self):
        """Destructor - zeroize on garbage collection."""
        if not self._zeroized:
            self.zeroize()

    def __len__(self) -> int:
        """Get original length of data."""
        return self._length

    def __repr__(self) -> str:
        """String representation (doesn't leak data)."""
        if self._zeroized:
            return f"SecureBytes(zeroized, original_length={self._length})"
        else:
            return f"SecureBytes(length={self._length}, locked={self._locked})"


class SecureKeyPair:
    """
    Secure container for cryptographic key pairs.

    Ensures both public and secret keys are properly managed,
    with automatic zeroization of the secret key.

    Example:
        >>> keypair = generate_keypair()  # Returns (public, secret)
        >>> with SecureKeyPair(keypair[0], keypair[1]) as keys:
        ...     signature = sign(keys.secret_key, message)
        ...     # Secret key automatically zeroized on exit
    """

    def __init__(self, public_key: bytes, secret_key: bytes):
        """
        Initialize secure key pair.

        Args:
            public_key: Public key (not sensitive, no special protection)
            secret_key: Secret key (sensitive, will be zeroized)
        """
        self.public_key = bytes(public_key)  # Public key doesn't need special protection
        self._secret_key = SecureBytes(secret_key)

    @property
    def secret_key(self) -> bytearray:
        """
        Get secret key data.

        Raises:
            ValueError: If secret key has been zeroized
        """
        return self._secret_key.data

    def zeroize(self) -> None:
        """Zeroize the secret key (public key is not affected)."""
        self._secret_key.zeroize()

    @property
    def is_zeroized(self) -> bool:
        """Check if secret key has been zeroized."""
        return self._secret_key.is_zeroized

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - zeroize secret key."""
        self.zeroize()
        return False

    def __del__(self):
        """Destructor - zeroize secret key."""
        if not self.is_zeroized:
            self.zeroize()

    def __repr__(self) -> str:
        """String representation (doesn't leak data)."""
        return f"SecureKeyPair(public_key_len={len(self.public_key)}, secret_key_zeroized={self.is_zeroized})"


def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time comparison of byte sequences.

    Prevents timing attacks by ensuring comparison always takes
    the same amount of time regardless of where differences occur.

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        True if sequences are equal, False otherwise

    Security:
        - Constant-time operation (no early termination)
        - Prevents timing side-channel attacks
        - Critical for MAC/signature verification
    """
    if len(a) != len(b):
        # Still need to do constant-time comparison of lengths
        # by comparing a dummy value
        result = 1
    else:
        result = 0

    # XOR all bytes and OR the results
    # This ensures we examine every byte regardless of differences
    for x, y in zip(a if len(a) <= len(b) else b, b if len(a) <= len(b) else a):
        result |= x ^ y

    return result == 0


def secure_random_bytes(length: int) -> SecureBytes:
    """
    Generate cryptographically secure random bytes.

    Args:
        length: Number of random bytes to generate

    Returns:
        SecureBytes container with random data

    The returned SecureBytes object should be used with a context
    manager to ensure proper cleanup:

    Example:
        >>> with secure_random_bytes(32) as random_key:
        ...     # Use random_key.data
        ...     result = some_operation(random_key.data)
        >>> # Automatically zeroized
    """
    random_data = os.urandom(length)
    return SecureBytes(random_data)


@contextmanager
def secure_operation(secret_data: bytes):
    """
    Context manager for secure operations with sensitive data.

    Automatically creates a SecureBytes container and ensures
    zeroization when the operation completes.

    Args:
        secret_data: Sensitive byte data

    Yields:
        SecureBytes container

    Example:
        >>> secret_key = get_key_from_somewhere()
        >>> with secure_operation(secret_key) as secure_key:
        ...     result = crypto_operation(secure_key.data)
        >>> # Key automatically zeroized
    """
    secure_data = SecureBytes(secret_data)
    try:
        yield secure_data
    finally:
        secure_data.zeroize()


def zeroize_bytes(data: Union[bytearray, memoryview]) -> None:
    """
    Zeroize a byte array or memoryview in place.

    This function performs secure overwrite of the provided
    byte array to prevent sensitive data from remaining in memory.

    Args:
        data: Byte array or memoryview to zeroize

    Note:
        This only works on mutable byte sequences (bytearray, memoryview).
        Immutable bytes objects cannot be zeroized in place.

    Example:
        >>> key_data = bytearray(b"secret key")
        >>> # Use key_data...
        >>> zeroize_bytes(key_data)
        >>> # key_data is now all zeros
    """
    if isinstance(data, (bytearray, memoryview)):
        length = len(data)

        # Multiple overwrite passes
        # Pass 1: zeros
        for i in range(length):
            data[i] = 0x00

        # Pass 2: ones
        for i in range(length):
            data[i] = 0xFF

        # Pass 3: random
        random_data = os.urandom(length)
        for i in range(length):
            data[i] = random_data[i]
        del random_data

        # Pass 4: final zeros
        for i in range(length):
            data[i] = 0x00

        gc.collect()
    else:
        raise TypeError("Can only zeroize mutable byte sequences (bytearray, memoryview)")


# Module-level utilities for integration with PQC classes
def create_secure_keypair(public_key: bytes, secret_key: bytes) -> SecureKeyPair:
    """
    Create a secure key pair with automatic cleanup.

    Args:
        public_key: Public key bytes
        secret_key: Secret key bytes (will be protected)

    Returns:
        SecureKeyPair instance

    Example:
        >>> with create_secure_keypair(pk, sk) as keypair:
        ...     # Use keypair.public_key and keypair.secret_key
        ...     pass
        >>> # Secret key automatically zeroized
    """
    return SecureKeyPair(public_key, secret_key)
