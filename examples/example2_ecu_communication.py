#!/usr/bin/env python3
"""
Example 2: Secure ECU-to-ECU Communication

Demonstrates secure communication between two ECUs using PQC.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.module4_invehicle_comm import ECUCryptoManager


def main():
    """Demonstrate ECU-to-ECU secure communication."""
    print("=" * 60)
    print("Example: Secure ECU-to-ECU Communication")
    print("=" * 60)

    # Initialize two ECUs
    print("\n1. Initializing ECUs...")
    ecu1 = ECUCryptoManager("ECU-ENGINE")
    ecu2 = ECUCryptoManager("ECU-BRAKE")

    # Establish secure session
    print("\n2. Establishing secure session...")
    session_key = ecu1.establish_session("ECU-BRAKE", ecu2.kem_keypair.public_key)
    print(f"   Session established: {len(session_key)} byte key")

    # Encrypt and send message
    print("\n3. ECU-ENGINE sends encrypted message to ECU-BRAKE...")
    plaintext = b"Engine RPM: 3500, Throttle: 75%"
    ciphertext = ecu1.encrypt_message("ECU-BRAKE", plaintext)
    print(f"   Plaintext: {plaintext.decode()}")
    print(f"   Ciphertext size: {len(ciphertext)} bytes")

    # Sign message
    print("\n4. ECU-ENGINE signs message...")
    signature = ecu1.sign_message(plaintext)
    print(f"   Signature size: {len(signature)} bytes")

    print("\n✓ Secure ECU communication demonstrated successfully!")


if __name__ == "__main__":
    main()
