class SODashboard:
    def display_event(self, event: dict):
        print("\n[SO DASHBOARD]")
        print("Smart Meter:", event["sm_id"])
        print("Gateway:", event["reg_id"])
        print("Time:", event["timestamp"])
        print("Status:", event["status"])
        print("Session Key Hash:", event["session_key_hash"])
