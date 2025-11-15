"""
BB84 Quantum Key Distribution Protocol

Implementation of the BB84 protocol (Bennett-Brassard, 1984) using Qiskit.
The first and most widely known QKD protocol.

Protocol Steps:
1. Alice generates random bits and random bases
2. Alice encodes qubits and sends to Bob
3. Bob measures qubits using random bases
4. Alice and Bob publicly compare bases
5. Discard bits where bases don't match (sifting)
6. Perform error correction and privacy amplification

Security:
- Provides information-theoretic security
- Detects eavesdropping via QBER (Quantum Bit Error Rate)
- Threshold QBER: ~11% for security

Automotive Use Cases:
- ECU master key distribution
- V2X encryption key establishment
- Critical infrastructure key refresh
"""

import secrets
from typing import Tuple, List, Optional
from dataclasses import dataclass
import numpy as np

try:
    from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
    from qiskit_aer import AerSimulator
    from qiskit.quantum_info import Statevector
    QISKIT_AVAILABLE = True
except ImportError:
    QISKIT_AVAILABLE = False
    print("WARNING: Qiskit not available. QKD simulation will use fallback mode.")


@dataclass
class BB84KeyPair:
    """BB84 key pair result."""

    alice_key: bytes
    bob_key: bytes
    qber: float  # Quantum Bit Error Rate
    sifted_key_length: int
    final_key_length: int

    def __repr__(self) -> str:
        return (
            f"BB84KeyPair(final_key_length={self.final_key_length}, "
            f"qber={self.qber:.4f}, sifted_length={self.sifted_key_length})"
        )


class BB84Protocol:
    """
    BB84 Quantum Key Distribution Protocol.

    Simulates the BB84 protocol using Qiskit for quantum operations.

    Example:
        >>> bb84 = BB84Protocol(num_qubits=1000)
        >>> key_pair = bb84.generate_key_pair()
        >>> print(f"Generated {len(key_pair.alice_key)} bytes")
        >>> print(f"QBER: {key_pair.qber:.2%}")

    Attributes:
        num_qubits: Number of qubits to transmit
        error_threshold: Maximum acceptable QBER (default 11%)
        use_qiskit: Whether Qiskit is available
    """

    def __init__(
        self,
        num_qubits: int = 1000,
        error_threshold: float = 0.11,
        noise_model: Optional[str] = None
    ):
        """
        Initialize BB84 protocol.

        Args:
            num_qubits: Number of qubits to use (more = longer key)
            error_threshold: Maximum QBER before aborting (default 11%)
            noise_model: Optional noise model ('depolarizing', 'bitflip')
        """
        self.num_qubits = num_qubits
        self.error_threshold = error_threshold
        self.noise_model = noise_model
        self.use_qiskit = QISKIT_AVAILABLE

        if self.use_qiskit:
            self.simulator = AerSimulator()

    def generate_key_pair(self) -> BB84KeyPair:
        """
        Generate a key pair using BB84 protocol.

        Returns:
            BB84KeyPair with Alice's and Bob's keys

        Raises:
            SecurityError: If QBER exceeds threshold
        """
        if self.use_qiskit:
            return self._generate_with_qiskit()
        else:
            return self._generate_fallback()

    def _generate_with_qiskit(self) -> BB84KeyPair:
        """Generate key pair using Qiskit simulation."""
        # Step 1: Alice generates random bits and bases
        alice_bits = [secrets.randbits(1) for _ in range(self.num_qubits)]
        alice_bases = [secrets.randbits(1) for _ in range(self.num_qubits)]  # 0=Z, 1=X

        # Step 2: Bob chooses random measurement bases
        bob_bases = [secrets.randbits(1) for _ in range(self.num_qubits)]

        # Step 3: Quantum transmission and measurement
        bob_results = []
        for i in range(self.num_qubits):
            # Create quantum circuit for this qubit
            qc = QuantumCircuit(1, 1)

            # Alice encodes her bit
            if alice_bits[i] == 1:
                qc.x(0)  # Apply X gate to encode |1>

            # Alice applies basis rotation if using X basis
            if alice_bases[i] == 1:
                qc.h(0)  # Hadamard for X basis

            # Simulate noisy channel (optional)
            if self.noise_model == 'bitflip':
                if secrets.randbelow(100) < 5:  # 5% bit flip probability
                    qc.x(0)
            elif self.noise_model == 'depolarizing':
                if secrets.randbelow(100) < 5:  # 5% depolarizing error
                    noise = secrets.randbelow(3)
                    if noise == 0:
                        qc.x(0)
                    elif noise == 1:
                        qc.z(0)
                    elif noise == 2:
                        qc.y(0)

            # Bob measures in his chosen basis
            if bob_bases[i] == 1:
                qc.h(0)  # Hadamard before measurement for X basis

            qc.measure(0, 0)

            # Execute circuit
            job = self.simulator.run(qc, shots=1)
            result = job.result()
            counts = result.get_counts()

            # Get measurement result (0 or 1)
            measured_bit = int(list(counts.keys())[0])
            bob_results.append(measured_bit)

        # Step 4: Sifting - keep only bits where bases match
        sifted_alice_bits = []
        sifted_bob_bits = []

        for i in range(self.num_qubits):
            if alice_bases[i] == bob_bases[i]:
                sifted_alice_bits.append(alice_bits[i])
                sifted_bob_bits.append(bob_results[i])

        # Step 5: Error estimation (use subset of bits)
        num_check_bits = min(len(sifted_alice_bits) // 2, 100)
        check_indices = secrets.SystemRandom().sample(
            range(len(sifted_alice_bits)),
            num_check_bits
        )

        errors = sum(
            1 for i in check_indices
            if sifted_alice_bits[i] != sifted_bob_bits[i]
        )
        qber = errors / num_check_bits if num_check_bits > 0 else 0.0

        # Check QBER threshold
        if qber > self.error_threshold:
            raise SecurityError(
                f"QBER {qber:.2%} exceeds threshold {self.error_threshold:.2%}. "
                "Possible eavesdropping detected!"
            )

        # Step 6: Remove check bits
        final_alice_bits = [
            sifted_alice_bits[i] for i in range(len(sifted_alice_bits))
            if i not in check_indices
        ]
        final_bob_bits = [
            sifted_bob_bits[i] for i in range(len(sifted_bob_bits))
            if i not in check_indices
        ]

        # Convert bits to bytes
        alice_key = self._bits_to_bytes(final_alice_bits)
        bob_key = self._bits_to_bytes(final_bob_bits)

        return BB84KeyPair(
            alice_key=alice_key,
            bob_key=bob_key,
            qber=qber,
            sifted_key_length=len(sifted_alice_bits),
            final_key_length=len(alice_key),
        )

    def _generate_fallback(self) -> BB84KeyPair:
        """
        Fallback implementation without Qiskit (for testing).
        Simulates BB84 using classical random number generation.
        """
        # Generate random bits for Alice
        alice_bits = [secrets.randbits(1) for _ in range(self.num_qubits)]
        alice_bases = [secrets.randbits(1) for _ in range(self.num_qubits)]

        # Generate random bases for Bob
        bob_bases = [secrets.randbits(1) for _ in range(self.num_qubits)]

        # Simulate measurement (Bob gets Alice's bit if bases match)
        bob_results = []
        for i in range(self.num_qubits):
            if alice_bases[i] == bob_bases[i]:
                # Bases match - Bob gets correct bit (with small error)
                if secrets.randbelow(100) < 5:  # 5% error rate
                    bob_results.append(1 - alice_bits[i])
                else:
                    bob_results.append(alice_bits[i])
            else:
                # Bases don't match - random result
                bob_results.append(secrets.randbits(1))

        # Sifting
        sifted_alice_bits = [
            alice_bits[i] for i in range(self.num_qubits)
            if alice_bases[i] == bob_bases[i]
        ]
        sifted_bob_bits = [
            bob_results[i] for i in range(self.num_qubits)
            if alice_bases[i] == bob_bases[i]
        ]

        # Error estimation
        num_check = min(len(sifted_alice_bits) // 2, 100)
        if num_check > 0:
            check_indices = secrets.SystemRandom().sample(
                range(len(sifted_alice_bits)),
                num_check
            )
            errors = sum(
                1 for i in check_indices
                if sifted_alice_bits[i] != sifted_bob_bits[i]
            )
            qber = errors / num_check
        else:
            qber = 0.0

        # Remove check bits
        final_alice_bits = [
            sifted_alice_bits[i] for i in range(len(sifted_alice_bits))
            if i not in (check_indices if num_check > 0 else [])
        ]
        final_bob_bits = [
            sifted_bob_bits[i] for i in range(len(sifted_bob_bits))
            if i not in (check_indices if num_check > 0 else [])
        ]

        # Convert to bytes
        alice_key = self._bits_to_bytes(final_alice_bits)
        bob_key = self._bits_to_bytes(final_bob_bits)

        return BB84KeyPair(
            alice_key=alice_key,
            bob_key=bob_key,
            qber=qber,
            sifted_key_length=len(sifted_alice_bits),
            final_key_length=len(alice_key),
        )

    def _bits_to_bytes(self, bits: List[int]) -> bytes:
        """Convert list of bits to bytes."""
        # Pad to multiple of 8
        padding = (8 - len(bits) % 8) % 8
        bits_padded = bits + [0] * padding

        # Convert to bytes
        byte_array = []
        for i in range(0, len(bits_padded), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits_padded[i + j]
            byte_array.append(byte)

        return bytes(byte_array)


class SecurityError(Exception):
    """Raised when QBER exceeds threshold."""
    pass


# Automotive helper functions
def generate_ecu_master_key(ecu_id: str, key_length_bits: int = 256) -> BB84KeyPair:
    """
    Generate master key for ECU using BB84.

    Args:
        ecu_id: ECU identifier
        key_length_bits: Desired key length in bits

    Returns:
        BB84KeyPair containing the distributed key

    Usage:
        Suitable for initial ECU provisioning or key refresh.
    """
    # Calculate required qubits (accounting for ~50% sifting loss)
    num_qubits = key_length_bits * 3  # 3x overhead for sifting + error correction

    bb84 = BB84Protocol(num_qubits=num_qubits, error_threshold=0.11)
    key_pair = bb84.generate_key_pair()

    print(f"Generated master key for ECU: {ecu_id}")
    print(f"  Key length: {key_pair.final_key_length} bytes")
    print(f"  QBER: {key_pair.qber:.4f}")
    print(f"  Sifting efficiency: {key_pair.sifted_key_length / num_qubits:.2%}")

    return key_pair
