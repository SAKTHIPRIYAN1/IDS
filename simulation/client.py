# client.py
# Smart Meter (SM)

import socket
import json
import time
import random
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto.sm import SmartMeter

SP_IP = "10.0.3.1"
SP_PORT = 9999
REG_PORT = 9998
SEND_INTERVAL = 3


def run_sender(sm_id):

    print(f"[*] Smart Meter {sm_id} starting")

    AUTH_LISTEN_PORT = 12000 + int(sm_id[2:])

    auth_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    auth_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    auth_listener.bind(("0.0.0.0", AUTH_LISTEN_PORT))
    auth_listener.listen(1)

    sm = SmartMeter(sm_id)

    sm.enroll()
    sm.authenticate()

    auth_payload = sm.build_auth_payload(b"AUTH_REQUEST", AUTH_LISTEN_PORT)

    sm_num = int(sm_id[2:])
    reg_ip = "10.0.1.254" if sm_num <= 5 else "10.0.2.254"

    try:

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((reg_ip, REG_PORT))

        sock.sendall(json.dumps(auth_payload).encode())
        sock.close()

        print("[SM] Waiting for SP authentication response...")
        print(f"[SM] Listening for SP JWT on port {AUTH_LISTEN_PORT}")

        conn, addr = auth_listener.accept()

        response = conn.recv(16384)

        print(f"[SM] Raw response: {response.decode()}")

        response_data = json.loads(response.decode())

        if response_data.get("status") == "success":
            token = response_data.get("token")
            print(f"[SM] Received JWT Token: {token}")

        conn.close()

    except Exception as e:
        print(f"[SM] Auth failed: {e}")
        return

    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[*] Sending usage to SP {SP_IP}:{SP_PORT}")

    try:

        while True:

            payload = {
                "smId": sm_id,
                "usage": round(random.uniform(0.5, 5.0), 2),
                "timestamp": time.time(),
                "token": token,
                "sm_ip": "10.0.1." + sm_id[2:] if sm_num <= 5 else "10.0.2." + str(int(sm_id[2:])-5),
                "sm_port": AUTH_LISTEN_PORT
            }

            udp_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))

            print(f"[SM → SP] usage={payload['usage']} kWh")

            time.sleep(SEND_INTERVAL)

    except KeyboardInterrupt:

        print("\n[*] Smart Meter stopped")

        udp_sock.close()


if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python3 client.py smX")
        sys.exit(1)

    run_sender(sys.argv[1])