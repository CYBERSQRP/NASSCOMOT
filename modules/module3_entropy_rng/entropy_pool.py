"""
Entropy Pool Management

Manages a pool of high-quality entropy for cryptographic operations.
Provides fast access to pre-generated random data.
"""

import threading
import time
from typing import Optional
from .hardware_rng import get_best_available_rng, HardwareRNG


class EntropyPool:
    """
    High-throughput entropy pool for automotive systems.

    Maintains a buffer of pre-generated entropy for fast access.
    """

    def __init__(
        self,
        pool_size: int = 4096,
        refill_threshold: int = 1024,
        rng: Optional[HardwareRNG] = None
    ):
        """
        Initialize entropy pool.

        Args:
            pool_size: Size of entropy pool in bytes
            refill_threshold: Refill when pool drops below this
            rng: Hardware RNG source (auto-selected if None)
        """
        self.pool_size = pool_size
        self.refill_threshold = refill_threshold
        self.rng = rng or get_best_available_rng()

        self._pool = bytearray()
        self._lock = threading.Lock()
        self._refill_pool()

        # Start background refill thread
        self._running = True
        self._refill_thread = threading.Thread(target=self._auto_refill, daemon=True)
        self._refill_thread.start()

    def get_bytes(self, num_bytes: int) -> bytes:
        """
        Get random bytes from pool.

        Args:
            num_bytes: Number of bytes to get

        Returns:
            Random bytes
        """
        with self._lock:
            if len(self._pool) < num_bytes:
                # Need immediate refill
                self._refill_pool()

            result = bytes(self._pool[:num_bytes])
            self._pool = self._pool[num_bytes:]

            return result

    def _refill_pool(self) -> None:
        """Refill the entropy pool."""
        needed = self.pool_size - len(self._pool)
        if needed > 0:
            new_entropy = self.rng.get_random_bytes(needed)
            self._pool.extend(new_entropy)

    def _auto_refill(self) -> None:
        """Background thread to auto-refill pool."""
        while self._running:
            time.sleep(0.1)  # Check every 100ms

            with self._lock:
                if len(self._pool) < self.refill_threshold:
                    self._refill_pool()

    def shutdown(self) -> None:
        """Shutdown the entropy pool."""
        self._running = False
        self._refill_thread.join(timeout=1.0)


# Global entropy pool instance
_global_pool: Optional[EntropyPool] = None


def get_global_pool() -> EntropyPool:
    """Get global entropy pool instance."""
    global _global_pool
    if _global_pool is None:
        _global_pool = EntropyPool()
    return _global_pool
