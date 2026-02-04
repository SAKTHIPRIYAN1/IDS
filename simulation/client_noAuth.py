# client.py
# Smart Meter (SM)

import socket
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto.sm import SmartMeter

SP_IP = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998
SEND_INTERVAL = 3


def run_sender(sm_id):
    print(f"[*] Smart Meter {sm_id} starting")

    # ---------- USAGE DATA ----------
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print(f"[*] Sending usage to SP {SP_IP}:{SP_PORT}")

    try:
        while True:
            payload = {
                "smId": sm_id,
                "usage": round(random.uniform(0.5, 5.0), 2),
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            udp_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            print(f"[SM → SP] usage={payload['usage']} kWh")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] Smart Meter stopped")
        udp_sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 client.py smX")
        sys.exit(1)

    run_sender(sys.argv[1])
