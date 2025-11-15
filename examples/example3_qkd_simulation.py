#!/usr/bin/env python3
"""
Example 3: QKD Simulation

Demonstrates quantum key distribution using BB84 protocol.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module2_qkd_layer import BB84Protocol, QKDManager, QKDProtocolType


def main():
    """Demonstrate QKD simulation."""
    print("=" * 60)
    print("Example: Quantum Key Distribution (BB84)")
    print("=" * 60)

    # Initialize BB84
    print("\n1. Initializing BB84 protocol (1000 qubits)...")
    bb84 = BB84Protocol(num_qubits=1000, error_threshold=0.11)

    # Generate key pair
    print("\n2. Generating quantum key pair...")
    key_pair = bb84.generate_key_pair()

    print(f"\n   Alice's key: {key_pair.alice_key.hex()[:64]}...")
    print(f"   Bob's key:   {key_pair.bob_key.hex()[:64]}...")
    print(f"   QBER: {key_pair.qber:.4f} ({key_pair.qber*100:.2f}%)")
    print(f"   Final key length: {key_pair.final_key_length} bytes")
    print(f"   Sifted key length: {key_pair.sifted_key_length} bits")

    if key_pair.alice_key == key_pair.bob_key:
        print("\n   ✓ Keys match! QKD successful!")
    else:
        print("\n   ✗ Keys don't match!")

    # Use QKD Manager
    print("\n3. Using QKD Manager for session management...")
    manager = QKDManager(default_key_lifetime_hours=24)

    session = manager.create_session(
        alice_id="ECU-1",
        bob_id="ECU-2",
        protocol=QKDProtocolType.BB84,
        num_qubits=1000
    )

    print(f"   Session ID: {session.session_id}")
    print(f"   Session key length: {len(session.shared_key)} bytes")


if __name__ == "__main__":
    main()
