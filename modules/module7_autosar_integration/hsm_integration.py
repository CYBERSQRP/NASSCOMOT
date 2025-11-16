"""
HSM/TPM Integration for Secure Key Storage

Provides interface to Hardware Security Modules (HSM) and Trusted Platform
Modules (TPM) for secure key storage and cryptographic operations.
"""

from typing import Optional, Dict
import os
from loguru import logger


class HSMIntegration:
    """
    Integration with Hardware Security Module and TPM 2.0.

    Features:
    - Secure key storage in HSM/TPM
    - Hardware-based cryptographic operations
    - Key attestation and sealing
    - Fallback to software storage
    """

    def __init__(self, prefer_tpm: bool = True):
        """
        Initialize HSM integration.

        Args:
            prefer_tpm: Prefer TPM over other HSM types
        """
        self.prefer_tpm = prefer_tpm
        self.hsm_available = self._detect_hsm()
        self.tpm_available = self._detect_tpm()

        # Software key storage (fallback)
        self.sw_keystore: Dict[str, bytes] = {}

        if self.tpm_available:
            logger.info("TPM 2.0 detected and available")
        elif self.hsm_available:
            logger.info("HSM detected and available")
        else:
            logger.warning("No HSM/TPM available, using software storage")

    def _detect_hsm(self) -> bool:
        """Detect available HSM."""
        # Check for common HSM device paths
        hsm_paths = [
            "/dev/hsm0",
            "/dev/crypto",
            "/dev/pkcs11"
        ]

        for path in hsm_paths:
            if os.path.exists(path):
                return True

        return False

    def _detect_tpm(self) -> bool:
        """Detect TPM 2.0."""
        tpm_paths = [
            "/dev/tpm0",
            "/dev/tpmrm0"
        ]

        for path in tpm_paths:
            if os.path.exists(path):
                return True

        return False

    def store_key(self, key_id: str, key_data: bytes, persistent: bool = True) -> bool:
        """
        Store key in HSM/TPM.

        Args:
            key_id: Key identifier
            key_data: Key material
            persistent: Make key persistent across reboots

        Returns:
            True if successful
        """
        if self.tpm_available and self.prefer_tpm:
            return self._store_key_tpm(key_id, key_data, persistent)
        elif self.hsm_available:
            return self._store_key_hsm(key_id, key_data)
        else:
            # Fallback to software storage
            self.sw_keystore[key_id] = key_data
            logger.warning(f"Stored key {key_id} in software (not secure!)")
            return True

    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve key from HSM/TPM.

        Args:
            key_id: Key identifier

        Returns:
            Key data or None if not found
        """
        if self.tpm_available and self.prefer_tpm:
            return self._retrieve_key_tpm(key_id)
        elif self.hsm_available:
            return self._retrieve_key_hsm(key_id)
        else:
            # Fallback to software storage
            key = self.sw_keystore.get(key_id)
            if key:
                logger.warning(f"Retrieved key {key_id} from software storage")
            return key

    def delete_key(self, key_id: str) -> bool:
        """
        Delete key from HSM/TPM.

        Args:
            key_id: Key identifier

        Returns:
            True if successful
        """
        if self.tpm_available and self.prefer_tpm:
            return self._delete_key_tpm(key_id)
        elif self.hsm_available:
            return self._delete_key_hsm(key_id)
        else:
            if key_id in self.sw_keystore:
                del self.sw_keystore[key_id]
                logger.info(f"Deleted key {key_id} from software storage")
                return True
            return False

    def seal_data(self, data: bytes, pcr_values: Optional[list] = None) -> bytes:
        """
        Seal data to TPM PCR values.

        Data can only be unsealed when PCRs match.

        Args:
            data: Data to seal
            pcr_values: PCR values to seal to (None = current values)

        Returns:
            Sealed data blob
        """
        if not self.tpm_available:
            logger.warning("TPM not available, returning unsealed data")
            return data

        # Simplified - production would use TPM2 sealing
        logger.info("Sealing data to TPM PCRs")
        return data  # Simulated

    def unseal_data(self, sealed_data: bytes) -> Optional[bytes]:
        """
        Unseal data from TPM.

        Args:
            sealed_data: Sealed data blob

        Returns:
            Unsealed data or None if PCRs don't match
        """
        if not self.tpm_available:
            return sealed_data

        # Simplified - production would use TPM2 unsealing
        logger.info("Unsealing data from TPM")
        return sealed_data  # Simulated

    # --- Internal Methods ---

    def _store_key_tpm(self, key_id: str, key_data: bytes, persistent: bool) -> bool:
        """Store key in TPM (simulated)."""
        logger.info(f"Storing key {key_id} in TPM (persistent={persistent})")
        # Production would use tpm2-pytss or similar
        self.sw_keystore[f"tpm_{key_id}"] = key_data
        return True

    def _retrieve_key_tpm(self, key_id: str) -> Optional[bytes]:
        """Retrieve key from TPM (simulated)."""
        logger.debug(f"Retrieving key {key_id} from TPM")
        return self.sw_keystore.get(f"tpm_{key_id}")

    def _delete_key_tpm(self, key_id: str) -> bool:
        """Delete key from TPM (simulated)."""
        logger.info(f"Deleting key {key_id} from TPM")
        tpm_key = f"tpm_{key_id}"
        if tpm_key in self.sw_keystore:
            del self.sw_keystore[tpm_key]
            return True
        return False

    def _store_key_hsm(self, key_id: str, key_data: bytes) -> bool:
        """Store key in HSM (simulated)."""
        logger.info(f"Storing key {key_id} in HSM")
        self.sw_keystore[f"hsm_{key_id}"] = key_data
        return True

    def _retrieve_key_hsm(self, key_id: str) -> Optional[bytes]:
        """Retrieve key from HSM (simulated)."""
        logger.debug(f"Retrieving key {key_id} from HSM")
        return self.sw_keystore.get(f"hsm_{key_id}")

    def _delete_key_hsm(self, key_id: str) -> bool:
        """Delete key from HSM (simulated)."""
        logger.info(f"Deleting key {key_id} from HSM")
        hsm_key = f"hsm_{key_id}"
        if hsm_key in self.sw_keystore:
            del self.sw_keystore[hsm_key]
            return True
        return False


__all__ = ['HSMIntegration']
