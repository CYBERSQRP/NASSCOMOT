"""
OTA Update Management with Post-Quantum Security

Manages secure OTA firmware updates with PQC signatures, anti-rollback
protection, and secure distribution channels.
"""

from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import struct
from loguru import logger

from .firmware_signer import FirmwareSigner


class UpdateStatus(Enum):
    """OTA update status."""
    PENDING = "pending"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    INSTALLING = "installing"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class FirmwarePackage:
    """Firmware update package."""
    version: str
    firmware_data: bytes
    signature: bytes
    metadata: Dict
    target_ecus: List[str]
    min_version: str  # For anti-rollback
    timestamp: datetime


@dataclass
class ECUUpdateState:
    """ECU update state tracking."""
    ecu_id: str
    current_version: str
    target_version: Optional[str]
    status: UpdateStatus
    download_progress: float  # 0.0 to 1.0
    last_update: datetime


class OTAManager:
    """
    Manages OTA updates with PQC security.

    Features:
    - PQC-signed firmware packages
    - Anti-rollback protection with version checking
    - Secure distribution over PQ-TLS
    - Progress tracking and verification
    - Automatic rollback on failure
    """

    def __init__(self, backend_url: str = "https://ota.example.com"):
        """
        Initialize OTA manager.

        Args:
            backend_url: OTA backend server URL
        """
        self.backend_url = backend_url
        self.signer = FirmwareSigner()

        # Track ECU update states
        self.ecu_states: Dict[str, ECUUpdateState] = {}

        # Track available updates
        self.available_updates: Dict[str, FirmwarePackage] = {}

        # Anti-rollback database
        self.min_versions: Dict[str, str] = {}

        logger.info(f"OTAManager initialized: backend={backend_url}")

    def register_ecu(
        self,
        ecu_id: str,
        current_version: str,
        min_version: str
    ) -> None:
        """
        Register ECU for OTA updates.

        Args:
            ecu_id: ECU identifier
            current_version: Current firmware version
            min_version: Minimum allowed version (anti-rollback)
        """
        self.ecu_states[ecu_id] = ECUUpdateState(
            ecu_id=ecu_id,
            current_version=current_version,
            target_version=None,
            status=UpdateStatus.PENDING,
            download_progress=0.0,
            last_update=datetime.now()
        )

        self.min_versions[ecu_id] = min_version

        logger.info(
            f"Registered ECU {ecu_id}: version={current_version}, "
            f"min_version={min_version}"
        )

    def create_update_package(
        self,
        firmware: bytes,
        version: str,
        target_ecus: List[str],
        metadata: Optional[Dict] = None
    ) -> FirmwarePackage:
        """
        Create signed firmware update package.

        Args:
            firmware: Firmware binary data
            version: Firmware version string
            target_ecus: List of target ECU IDs
            metadata: Optional metadata

        Returns:
            Signed firmware package
        """
        # Sign firmware
        signature = self.signer.sign_firmware(firmware, version, ",".join(target_ecus))

        # Determine minimum version for anti-rollback
        min_version = "0.0.0"
        for ecu_id in target_ecus:
            if ecu_id in self.min_versions:
                if self._compare_versions(self.min_versions[ecu_id], min_version) > 0:
                    min_version = self.min_versions[ecu_id]

        # Create package
        package = FirmwarePackage(
            version=version,
            firmware_data=firmware,
            signature=signature,
            metadata=metadata or {},
            target_ecus=target_ecus,
            min_version=min_version,
            timestamp=datetime.now()
        )

        # Store in available updates
        self.available_updates[version] = package

        logger.info(
            f"Created update package: version={version}, "
            f"targets={len(target_ecus)}, size={len(firmware)} bytes"
        )

        return package

    def distribute_update(
        self,
        version: str,
        target_ecus: Optional[List[str]] = None
    ) -> Dict[str, bool]:
        """
        Distribute firmware update to ECUs.

        Args:
            version: Firmware version to distribute
            target_ecus: Optional list of specific ECUs (default: all)

        Returns:
            Dictionary of ecu_id -> success status
        """
        if version not in self.available_updates:
            logger.error(f"Update version {version} not found")
            return {}

        package = self.available_updates[version]

        # Determine targets
        if target_ecus is None:
            target_ecus = package.target_ecus

        results = {}

        for ecu_id in target_ecus:
            if ecu_id not in self.ecu_states:
                logger.warning(f"ECU {ecu_id} not registered")
                results[ecu_id] = False
                continue

            # Check anti-rollback
            if not self._check_rollback(ecu_id, version):
                logger.error(
                    f"Anti-rollback violation for {ecu_id}: "
                    f"version {version} < min {self.min_versions[ecu_id]}"
                )
                results[ecu_id] = False
                continue

            # Update state
            state = self.ecu_states[ecu_id]
            state.target_version = version
            state.status = UpdateStatus.DOWNLOADING
            state.download_progress = 0.0
            state.last_update = datetime.now()

            # Simulate distribution (production would use PQ-TLS)
            success = self._send_to_ecu(ecu_id, package)
            results[ecu_id] = success

            if success:
                logger.info(f"Distributed update {version} to {ecu_id}")
            else:
                logger.error(f"Failed to distribute update to {ecu_id}")
                state.status = UpdateStatus.FAILED

        return results

    def verify_and_install(
        self,
        ecu_id: str,
        package: FirmwarePackage
    ) -> bool:
        """
        Verify and install firmware on ECU.

        Args:
            ecu_id: ECU identifier
            package: Firmware package

        Returns:
            True if installation successful
        """
        if ecu_id not in self.ecu_states:
            return False

        state = self.ecu_states[ecu_id]
        state.status = UpdateStatus.VERIFYING

        # Verify signature
        if not self.signer.verify_firmware(
            package.firmware_data,
            package.version,
            ecu_id,
            package.signature
        ):
            logger.error(f"Signature verification failed for {ecu_id}")
            state.status = UpdateStatus.FAILED
            return False

        # Verify hash
        computed_hash = hashlib.sha384(package.firmware_data).hexdigest()
        expected_hash = package.metadata.get('sha384')
        if expected_hash and computed_hash != expected_hash:
            logger.error(f"Hash mismatch for {ecu_id}")
            state.status = UpdateStatus.FAILED
            return False

        # Install (simulated)
        state.status = UpdateStatus.INSTALLING
        logger.info(f"Installing firmware {package.version} on {ecu_id}")

        # Update version
        state.current_version = package.version
        state.target_version = None
        state.status = UpdateStatus.COMPLETED
        state.last_update = datetime.now()

        # Update min version for anti-rollback
        if self._compare_versions(package.version, self.min_versions[ecu_id]) > 0:
            self.min_versions[ecu_id] = package.version

        logger.info(f"Successfully installed {package.version} on {ecu_id}")
        return True

    def rollback(self, ecu_id: str, target_version: str) -> bool:
        """
        Rollback ECU to previous firmware version.

        Args:
            ecu_id: ECU identifier
            target_version: Version to rollback to

        Returns:
            True if rollback successful
        """
        if ecu_id not in self.ecu_states:
            return False

        # Check anti-rollback
        if not self._check_rollback(ecu_id, target_version):
            logger.error(f"Cannot rollback {ecu_id} to {target_version} (anti-rollback)")
            return False

        state = self.ecu_states[ecu_id]
        logger.warning(f"Rolling back {ecu_id} to {target_version}")

        state.current_version = target_version
        state.status = UpdateStatus.ROLLED_BACK
        state.last_update = datetime.now()

        return True

    def get_ecu_status(self, ecu_id: str) -> Optional[ECUUpdateState]:
        """Get ECU update status."""
        return self.ecu_states.get(ecu_id)

    def _check_rollback(self, ecu_id: str, version: str) -> bool:
        """Check if version violates anti-rollback policy."""
        if ecu_id not in self.min_versions:
            return True

        min_version = self.min_versions[ecu_id]
        return self._compare_versions(version, min_version) >= 0

    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare version strings.

        Returns:
            -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        parts1 = [int(x) for x in v1.split('.')]
        parts2 = [int(x) for x in v2.split('.')]

        for p1, p2 in zip(parts1, parts2):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1

        if len(parts1) < len(parts2):
            return -1
        elif len(parts1) > len(parts2):
            return 1

        return 0

    def _send_to_ecu(self, ecu_id: str, package: FirmwarePackage) -> bool:
        """
        Send firmware package to ECU (simulated).

        Production would use PQ-TLS secure channel.

        Args:
            ecu_id: Target ECU
            package: Firmware package

        Returns:
            True if sent successfully
        """
        # Simulated transmission
        logger.debug(f"Sending {len(package.firmware_data)} bytes to {ecu_id}")
        return True


__all__ = ['OTAManager', 'FirmwarePackage', 'UpdateStatus', 'ECUUpdateState']
