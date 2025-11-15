"""OTA Update Management"""

class OTAManager:
    """Manages OTA updates with PQC security."""
    
    def __init__(self):
        from .firmware_signer import FirmwareSigner
        self.signer = FirmwareSigner()
    
    def distribute_update(self, firmware: bytes, version: str, target_ecus: list) -> None:
        """Distribute firmware update to ECUs."""
        for ecu_id in target_ecus:
            package = self.signer.sign_firmware(firmware, version, ecu_id)
            print(f"Distributing update {version} to {ecu_id}")
            # Send via PQ-TLS channel
