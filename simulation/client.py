# client.py
# Smart Meter (SM)
# inp provider


import socket
import json
import time
import random
import sys

SP_IP = "10.0.3.1"
SP_PORT = 9999

SEND_INTERVAL = 3  


def run_sender(sm_id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[*] Smart Meter {sm_id} started")
    print(f"[*] Sending to SP {SP_IP}:{SP_PORT}")
    print("Press CTRL+C to stop\n")

    try:
        while True:
            payload = {
                "smId": sm_id,
                "usage": round(random.uniform(0.5, 5.0), 2),
                "proto": "udp",
                "service": "-",
                "timestamp": time.time()
            }

            message = json.dumps(payload).encode()
            sock.sendto(message, (SP_IP, SP_PORT))

            print(f"[SM → SP] usage={payload['usage']} kWh")
            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] Smart Meter stopped")
        sock.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 client.py <smId>")
        sys.exit(1)

    run_sender(sys.argv[1])
