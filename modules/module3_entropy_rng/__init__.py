"""
Module 3: Entropy & RNG Engine

Provides high-quality entropy sources and cryptographic RNG for automotive systems.

Components:
- Hardware RNG integration (Radioactive, Quantum Optical)
- FIPS-140-3 entropy testing
- High-throughput entropy pool
- Secure seed generation

Compliance: FIPS-140-3, ISO/SAE 21434 Section 9.3.1
"""

__version__ = "1.0.0"

from .hardware_rng import HardwareRNG, QuantumRNG, RadioactiveRNG
from .entropy_pool import EntropyPool
from .fips_tests import FIPSEntropyTester
from .secure_random import SecureRandom

__all__ = [
    "HardwareRNG",
    "QuantumRNG",
    "RadioactiveRNG",
    "EntropyPool",
    "FIPSEntropyTester",
    "SecureRandom",
]
