"""VIN-based Identity Management"""

class VINIdentityManager:
    """Manage ECU identities based on VIN."""
    
    def __init__(self):
        self.identities = {}
    
    def register_ecu(self, vin: str, ecu_id: str, public_key: bytes) -> None:
        """Register ECU for a vehicle."""
        if vin not in self.identities:
            self.identities[vin] = []
        
        self.identities[vin].append({
            "ecu_id": ecu_id,
            "public_key": public_key
        })
        
        print(f"Registered ECU {ecu_id} for VIN {vin}")
    
    def get_ecus_for_vin(self, vin: str) -> list:
        """Get all ECUs for a VIN."""
        return self.identities.get(vin, [])
