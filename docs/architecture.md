# NASSCOMOT Architecture Documentation

## System Architecture

NASSCOMOT implements a layered architecture for quantum-safe automotive security:

```
┌─────────────────────────────────────────────────────────────┐
│              Application Layer (AUTOSAR Apps)                │
├─────────────────────────────────────────────────────────────┤
│  Module 8: HIL Demo    │  Module 7: AUTOSAR Integration     │
├─────────────────────────────────────────────────────────────┤
│  Module 6: OTA Security │ Module 5: V2X Messaging           │
├─────────────────────────────────────────────────────────────┤
│  Module 4: In-Vehicle Communication (CAN, Ethernet)         │
├─────────────────────────────────────────────────────────────┤
│  Module 2: QKD Simulation │ Module 3: Entropy & RNG         │
├─────────────────────────────────────────────────────────────┤
│  Module 1: Post-Quantum Cryptography Layer                  │
│  (ML-KEM, ML-DSA, SLH-DSA, Hybrid TLS)                      │
├─────────────────────────────────────────────────────────────┤
│           Hardware Layer (HSM, TPM, Quantum RNG)            │
└─────────────────────────────────────────────────────────────┘
```

## Module Details

### Module 1: Quantum-Safe Cryptography Layer

**Purpose**: Core PQC primitives for all higher layers

**Components**:
- ML-KEM (FIPS 203): Key encapsulation for secure key exchange
- ML-DSA (FIPS 204): Digital signatures for authentication
- SLH-DSA (FIPS 205): Hash-based signatures for long-term security
- Hybrid TLS: Combines classical (X25519/P-256) with PQC

**Key Interfaces**:
```python
# Key Exchange
kem = MLKEM768()
public_key, secret_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(public_key)

# Digital Signature
dsa = MLDSA65()
signing_key, verify_key = dsa.generate_keypair()
signature = dsa.sign(signing_key, message)
valid = dsa.verify(verify_key, message, signature)
```

### Module 2: QKD Simulation Layer

**Purpose**: Quantum key distribution for ultra-secure key establishment

**Components**:
- BB84 Protocol: Bennett-Brassard 1984 protocol
- E91 Protocol: Entanglement-based QKD
- QKD Manager: Session management and key lifecycle
- Privacy Amplification: Extract secure key from raw QKD output

**Use Cases**:
- ECU master key distribution
- V2X encryption key establishment
- Critical infrastructure key refresh

### Module 3: Entropy & RNG Engine

**Purpose**: High-quality randomness for cryptographic operations

**Components**:
- Hardware RNG: Quantum optical, radioactive decay, TPM 2.0
- Entropy Pool: High-throughput buffer for fast access
- FIPS Tester: Validate RNG quality per FIPS 140-3

**Integration**:
All cryptographic operations use this module for random number generation.

### Module 4: In-Vehicle Secure Communication

**Purpose**: Secure ECU-to-ECU communication

**Supported Networks**:
- CAN / CAN-FD
- Automotive Ethernet (100BASE-T1, 1000BASE-T1)
- SOME/IP-SD
- FlexRay

**Security Features**:
- PQC key exchange between ECU pairs
- Encrypted message frames
- VLAN-based segmentation
- Legacy ECU fallback (hybrid mode)

### Module 5: V2X Quantum-Secure Messaging

**Purpose**: Secure vehicle-to-everything communication

**Protocols**:
- DSRC/ITS-G5 with PQC signatures (IEEE 1609.2 compatible)
- 5G C-V2X with PQ-TLS
- OTA updates for roadside units (RSUs)

**Message Types**:
- BSM (Basic Safety Message)
- CAM (Cooperative Awareness Message)
- DENM (Decentralized Environmental Notification Message)

### Module 6: OTA Update Security

**Purpose**: Secure firmware updates and telemetry

**Features**:
- PQC-signed firmware packages (ML-DSA)
- Secure OTA distribution channels (PQ-TLS)
- Anti-rollback protection
- Encrypted telemetry transmission

**Update Flow**:
1. Cloud signs firmware with ML-DSA
2. ECU verifies signature before installation
3. Integrity check post-installation
4. Rollback if verification fails

### Module 7: AUTOSAR Adaptive Integration

**Purpose**: Integration with AUTOSAR Adaptive Platform

**Components**:
- AUTOSAR Crypto Stack adapter
- HSM/TPM integration
- Real-time performance optimization
- ASIL-D compliance validation

**API Compatibility**:
Compatible with AUTOSAR Adaptive Crypto API for drop-in integration.

### Module 8: HIL Demonstration & Benchmarking

**Purpose**: Hardware-in-loop testing and performance measurement

**Supported Platforms**:
- NVIDIA Orin AGX
- dSPACE platforms
- NXP S32 series

**Benchmarks**:
- Key generation latency
- Signature/verification time
- Encryption throughput
- Memory usage

## Data Flow

### ECU-to-ECU Secure Communication

```
ECU-1                                    ECU-2
  │                                        │
  ├─ Generate ML-KEM keypair              ├─ Generate ML-KEM keypair
  │                                        │
  ├──── Send public key ───────────────>  │
  │                                        │
  │  <──── Send public key ───────────────┤
  │                                        │
  ├─ Encapsulate shared secret            │
  │                                        │
  ├─ Encrypt message with AES-GCM         │
  │                                        │
  ├──── Send encrypted message ────────>  │
  │                                        │
  │                          Decrypt ──────┤
  │                                        │
```

### V2X Message Signing

```
Vehicle                               RSU/Other Vehicle
  │                                        │
  ├─ Generate BSM data                     │
  │                                        │
  ├─ Sign with ML-DSA                      │
  │                                        │
  ├──── Broadcast BSM + Signature ──────> │
  │                                        │
  │                    Verify signature ───┤
  │                                        │
  │                    Process if valid ───┤
```

### OTA Firmware Update

```
Cloud Server                          ECU
  │                                    │
  ├─ Build firmware                    │
  │                                    │
  ├─ Sign with ML-DSA                  │
  │                                    │
  ├──── Send firmware package ──────>  │
  │                                    │
  │               Verify signature ────┤
  │                                    │
  │               Install if valid ────┤
  │                                    │
  │  <──── Send confirmation ──────────┤
```

## Performance Targets

| Operation | Target Latency | Platform |
|-----------|---------------|----------|
| ML-KEM-768 KeyGen | < 50 μs | NVIDIA Orin |
| ML-KEM-768 Encaps | < 50 μs | NVIDIA Orin |
| ML-DSA-65 Sign | < 200 μs | NVIDIA Orin |
| ML-DSA-65 Verify | < 100 μs | NVIDIA Orin |
| V2X Message Sign | < 10 ms | Production ECU |
| ECU Handshake | < 100 ms | CAN-FD |

## Security Properties

### Quantum Resistance

All cryptographic operations use NIST-standardized PQC algorithms:
- **ML-KEM**: Secure against quantum attacks on lattice problems
- **ML-DSA**: Secure against quantum attacks on lattice problems
- **SLH-DSA**: Secure based only on hash function security

### Forward Secrecy

- Session keys are ephemeral (not derived from long-term keys)
- Compromise of long-term keys doesn't compromise past sessions
- Implemented via ML-KEM encapsulation

### Authentication

- All messages signed with ML-DSA
- Certificate-based authentication for V2X
- ECU identity verification before communication

## Compliance Mapping

See [compliance_mapping.md](compliance_mapping.md) for detailed mapping to:
- ISO/SAE 21434
- UNECE R155/R156
- FIPS 140-3
- AUTOSAR Adaptive Platform specifications
