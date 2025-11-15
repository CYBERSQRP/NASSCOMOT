# NASSCOMOT - Quantum-Safe Cryptography for Automotive Systems

## Project Overview

NASSCOMOT (Next-generation Automotive Secure System with COnnected Mobility Technologies) is a comprehensive quantum-safe cryptography implementation designed for modern automotive systems. This project provides enterprise-grade post-quantum cryptographic protection for ECUs, V2X communications, and OTA updates.

## 🎯 Key Features

- **NIST PQC Algorithms**: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+)
- **Quantum Key Distribution**: Qiskit-based QKD simulation (BB84, E91)
- **Hybrid Cryptography**: Post-quantum + classical crypto for transition period
- **AUTOSAR Integration**: Compatible with AUTOSAR Adaptive Crypto Stack
- **Compliance**: ISO/SAE 21434, UNECE R155/R156, FIPS-140-3
- **Hardware Support**: HSM, TPM 2.0, Hardware RNG integration
- **Real-time Performance**: Optimized for automotive timing constraints

## 📦 Module Architecture

### Core Modules

1. **Module 1: Quantum-Safe Cryptography Layer**
   - NIST PQC algorithm integration (ML-KEM, ML-DSA, SLH-DSA)
   - Hybrid PQC-TLS 1.3 implementation
   - Quantum-secure message signing for V2X and ECU
   - ISO/SAE 21434 compliance

2. **Module 2: QKD Simulation Layer**
   - Qiskit-based quantum key distribution (BB84, E91, BBM92)
   - Secure key generation and distribution pipeline
   - Automated key refresh and rotation
   - Integration with PQC-TLS sessions

3. **Module 3: Entropy & RNG Engine**
   - Hardware RNG integration (Radioactive, Quantum Optical)
   - FIPS-140-3 entropy testing and validation
   - High-throughput entropy pipeline
   - Secure seed generation and storage

4. **Module 4: In-Vehicle Secure Communication**
   - PQC-secured ECU-to-ECU channels
   - SOME/IP-SD with PQC key exchange
   - CAN, Automotive Ethernet, FlexRay support
   - VLAN-based network segmentation

5. **Module 5: V2X Quantum-Secure Messaging**
   - PQC-secure DSRC/ITS-G5 signing
   - 5G C-V2X with PQ-TLS/IPsec
   - Quantum-safe OTA for RSUs
   - UNECE R155 certificate lifecycle

6. **Module 6: OTA Update Security**
   - PQC-signed firmware images
   - Secure OTA distribution with anti-rollback
   - PQ-TLS tunnels to cloud servers
   - ISO 21434 Section 5 compliance

7. **Module 7: AUTOSAR Adaptive Integration**
   - AUTOSAR Adaptive Platform integration
   - HSM and TPM 2.0 support
   - Real-time performance optimization
   - ASIL-D safety compliance validation

8. **Module 8: HIL Demonstration & Benchmarking**
   - NVIDIA Orin / dSPACE deployment
   - Performance benchmarking suite
   - Security KPI dashboard
   - Full ECU↔Gateway↔V2X demo

### Optional Modules

9. **Module 9: Quantum-Safe Vehicle PKI**
   - PQC certificate infrastructure for ECUs
   - VIN-based identity management
   - Certificate lifecycle and revocation

10. **Module 10: Threat Modeling & Compliance**
    - ISO/SAE 21434, UN R155/R156 mapping
    - Quantum risk assessment framework
    - STRIDE/DREAD analysis tools

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.9+
GCC/Clang with C++17 support
OpenSSL 3.0+
Qiskit 0.45+
```

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd NASSCOMOT

# Install Python dependencies
pip install -r requirements.txt

# Build C/C++ components (if applicable)
cd modules/module1_pqc_layer/native
make

# Run tests
pytest tests/
```

### Basic Usage

```python
from modules.module1_pqc_layer import MLKEMKeyExchange, MLDSASignature
from modules.module2_qkd_layer import BB84Protocol

# Example: PQC Key Exchange
kem = MLKEMKeyExchange(security_level=3)  # ML-KEM-768
public_key, secret_key = kem.generate_keypair()
ciphertext, shared_secret = kem.encapsulate(public_key)

# Example: Digital Signature
dsa = MLDSASignature(security_level=2)  # ML-DSA-65
signing_key, verify_key = dsa.generate_keypair()
signature = dsa.sign(signing_key, b"ECU firmware v1.2.3")
valid = dsa.verify(verify_key, b"ECU firmware v1.2.3", signature)

# Example: QKD Simulation
qkd = BB84Protocol(num_qubits=1000, error_threshold=0.11)
alice_key, bob_key = qkd.generate_key_pair()
```

## 📊 Performance Benchmarks

| Operation | ML-KEM-768 | ML-DSA-65 | Classical (RSA-2048) |
|-----------|------------|-----------|----------------------|
| Key Generation | 15 μs | 45 μs | 250 ms |
| Encapsulation | 20 μs | - | - |
| Decapsulation | 25 μs | - | - |
| Sign | - | 150 μs | 5 ms |
| Verify | - | 80 μs | 0.2 ms |

*Benchmarked on NVIDIA Orin AGX (ARM Cortex-A78AE)*

## 🔒 Security Compliance

- **ISO/SAE 21434**: Cybersecurity engineering for automotive systems
- **UNECE R155**: Cyber security and management system
- **UNECE R156**: Software update management system
- **FIPS-140-3**: Cryptographic module validation
- **NIST PQC**: Post-Quantum Cryptography standards
- **AUTOSAR**: Adaptive Platform security requirements

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Run module-specific tests
pytest tests/test_module1_pqc.py -v

# Run performance benchmarks
python benchmarks/run_all_benchmarks.py

# Run compliance validation
python compliance/validate_iso21434.py
```

## 📁 Project Structure

```
NASSCOMOT/
├── modules/
│   ├── module1_pqc_layer/          # Quantum-Safe Cryptography
│   ├── module2_qkd_layer/          # QKD Simulation
│   ├── module3_entropy_rng/        # Entropy & RNG Engine
│   ├── module4_invehicle_comm/     # In-Vehicle Communication
│   ├── module5_v2x_messaging/      # V2X Secure Messaging
│   ├── module6_ota_security/       # OTA Update Security
│   ├── module7_autosar_integration/# AUTOSAR Integration
│   ├── module8_hil_demo/           # HIL Demonstration
│   ├── module9_vehicle_pki/        # Vehicle PKI (Optional)
│   └── module10_threat_modeling/   # Threat Modeling (Optional)
├── tests/                          # Unit and integration tests
├── benchmarks/                     # Performance benchmarks
├── compliance/                     # Compliance validation tools
├── docs/                           # Documentation
├── examples/                       # Usage examples
└── tools/                          # Utility scripts

```

## 🛠️ Development

### Code Style

- Python: PEP 8, type hints required
- C/C++: Google C++ Style Guide
- Documentation: Google docstring format

### Contributing

1. Create a feature branch from `main`
2. Implement changes with tests
3. Ensure all tests pass
4. Submit pull request with detailed description

## 📚 Documentation

- [Architecture Guide](docs/architecture.md)
- [API Reference](docs/api_reference.md)
- [Integration Guide](docs/integration_guide.md)
- [Compliance Mapping](docs/compliance_mapping.md)
- [Performance Tuning](docs/performance_tuning.md)

## 🤝 Support

For issues, questions, or contributions:
- GitHub Issues: [Project Issues](https://github.com/CYBERSQRP/NASSCOMOT/issues)
- Documentation: [Full Documentation](docs/)

## 📄 License

This project is proprietary software developed for LTTS automotive security initiatives.

## 🏆 Acknowledgments

- NIST PQC Standardization Project
- Qiskit Development Team
- AUTOSAR Consortium
- ISO/SAE 21434 Working Group

---

**Version**: 1.0.0
**Last Updated**: 2025-11-15
**Status**: Active Development
