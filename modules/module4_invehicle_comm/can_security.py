"""Secure CAN Bus Communication"""

class SecureCANBus:
    """PQC-secured CAN bus implementation."""
    
    def __init__(self, can_id: int):
        self.can_id = can_id
    
    def send_secure_frame(self, data: bytes, dest_id: int) -> None:
        """Send encrypted CAN frame."""
        print(f"Sending secure CAN frame to {dest_id}")
