# client.py
# Smart Meter (SM)
# inp provider


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

SEND_INTERVAL = 3  


def run_sender(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[*] Smart Meter {sm_id} started")

    # PQC Auth
    sm = SmartMeter(sm_id)
    sm.enroll()
    sm.authenticate()
    auth_payload = sm.build_auth_payload(b"AUTH_REQUEST")

    # Determine REG IP
    sm_num = int(sm_id[2:])
    reg_ip = "10.0.1.254" if sm_num <= 5 else "10.0.2.254"
    reg_port = 9998

    # Send auth to REG
    sock.sendto(json.dumps(auth_payload).encode(), (reg_ip, reg_port))
    print(f"[SM → REG] Auth sent to {reg_ip}:{reg_port}")

    print(f"[*] Sending usage to SP {SP_IP}:{SP_PORT}")
    print("Press CTRL+C to stop\n")

    try:
        while True:
            payload = {
                "smId": sm_id,
                "usage": round(random.uniform(0.5, 5.0), 2),
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            message = json.dumps(payload).encode()
            sock.sendto(message, (SP_IP, SP_PORT))

            print(f"[SM → SP] usage={payload['usage']} kWh")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] Smart Meter stopped")
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <smId>")
        sys.exit(1)

    run_sender(sys.argv[1])
