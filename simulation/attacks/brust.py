# burst_attack.py
# Temporal Burst Attack (SM → SP)

import socket
import json
import time
import random
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

REG_MAP = {
    "sm1": "10.0.1.254", "sm2": "10.0.1.254", "sm3": "10.0.1.254",
    "sm4": "10.0.1.254", "sm5": "10.0.1.254",
    "sm6": "10.0.2.254", "sm7": "10.0.2.254", "sm8": "10.0.2.254",
    "sm9": "10.0.2.254", "sm10": "10.0.2.254"
}

# -------- BURST CONFIG --------
BURST_SIZE = 12              # packets per burst
BURST_INTERVAL = 0.01        # very fast inside burst
IDLE_TIME = 6.0              # long silence → temporal anomaly


def run_burst(sm_id):
    if sm_id not in REG_MAP:
        print("[ERROR] Invalid SM ID")
        return

    reg_ip = REG_MAP[sm_id]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[⚠️ TEMPORAL BURST ATTACK STARTED]")
    print(f"[!] SM ID          : {sm_id}")
    print(f"[!] REG ID         : {reg_ip}")
    print(f"[!] SP Target      : {SP_IP}:{SP_PORT}")
    print(f"[!] Burst size     : {BURST_SIZE}")
    print(f"[!] Burst interval : {BURST_INTERVAL}s")
    print(f"[!] Idle time      : {IDLE_TIME}s")
    print("-" * 50)

    try:
        while True:
            # -------- BURST PHASE --------
            for _ in range(BURST_SIZE):
                payload = {
                    "reg_id": reg_ip,
                    "smId": sm_id,
                    "usage": round(random.uniform(1.0, 3.0), 2),  # normal usage
                    "proto": "udp",
                    "service": "-",
                    "timestamp": time.time()
                }

                sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
                time.sleep(BURST_INTERVAL)

            # -------- SILENT PHASE --------
            time.sleep(IDLE_TIME)

    except KeyboardInterrupt:
        print("\n[!] TEMPORAL BURST ATTACK STOPPED")
        sock.close()


# ---------------- MAIN ----------------
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 burst_attack.py <smId>")
        sys.exit(1)

    run_burst(sys.argv[1])
