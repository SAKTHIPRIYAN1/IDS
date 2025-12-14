#  this my code for the Smart Meter (SM) client
#  to send data to Service Provider (SP)
#  through REG forwarding

import socket
import json
import time
import random
import sys

from event_emitter import emit

emit("sm1","regS1")
emit("regS1","reg1")


# Configuration
SP_PORT = 9999

TARGET_IP = '10.0.3.1'

def run_sender(sm_id):
    # 1. auto-detect the correct SP address
    target_ip = TARGET_IP
    
    # 2. Setup UDP Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[*] Smart Meter {sm_id} Initialized.")
    print(f"[*] Target SP Address: {target_ip}:{SP_PORT}")
    print("Press CTRL+C to stop.")

    try:
        while True:
            # 3. Generate Simulation Data
            # Random usage between 0.5 kWh and 5.0 kWh
            usage_val = round(random.uniform(0.5, 5.0), 2)
            
            payload = {
                "smId": sm_id,
                "timestamp": time.time(),
                "usage": usage_val,
                "targetIp": target_ip, # Sending this just for debug verification
                "status": "OK"
            }
            
            # 4. Send Packet
            message = json.dumps(payload).encode()
            s.sendto(message, (target_ip, SP_PORT))
            
            print(f" -> Sent {usage_val} kWh to SP")
            
            # Wait 3 seconds
            time.sleep(3)
            
    except KeyboardInterrupt:
        print("\n[*] Stopping Meter...")
        s.close()

if __name__ == "__main__":
    # check for argument for sm_id
    if len(sys.argv) < 2:
        print("Usage: python3 client.py <sm_name>")
        print("Example: python3 client.py sm1")
        sys.exit(1)
        
    myId = sys.argv[1]
    run_sender(myId)



    
