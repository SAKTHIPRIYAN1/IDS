# recon_attack.py
# UNSW-style Reconnaissance Smart Meter

import socket
import json
import time
import random
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

# Recon pattern
BURST_SIZE = 20          # packets per burst
BURST_INTERVAL = 0.02    # fast probing
SLEEP_BETWEEN = 2.0      # idle gap (important!)

def run_recon(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[*] RECON ATTACK CLIENT STARTED")
    print(f"[*] Burst size      : {BURST_SIZE}")
    print(f"[*] Burst interval  : {BURST_INTERVAL}s")
    print(f"[*] Sleep between   : {SLEEP_BETWEEN}s")
    print("-" * 50)

    while True:
        # --- Burst ---
        for _ in range(BURST_SIZE):
            msg = {
                "smId": sm_id,
                "usage": round(random.uniform(0.1, 0.3), 2),
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }
            sock.sendto(json.dumps(msg).encode(), (SP_IP, SP_PORT))
            time.sleep(BURST_INTERVAL)

        # --- Idle gap ---
        time.sleep(SLEEP_BETWEEN)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 recon_attack.py <smId>")
        sys.exit(1)

    run_recon(sys.argv[1])
