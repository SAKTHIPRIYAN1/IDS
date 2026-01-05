# so_forwarder.py
# System Operator (SO)
# Receives STATUS / ALERT from Service Provider (SP)
# Forwards to Host Dashboard (with XAI)

import socket
import json
import os
import datetime

SO_LISTEN_IP = "0.0.0.0"
SO_LISTEN_PORT = 9999

HOST_DASHBOARD_IP = "172.17.250.1"
HOST_DASHBOARD_PORT = 8888


def check_interface():
    print("\n[CHECK] Listing SO network interfaces:")
    os.system("ip addr show")

    print("\n[CHECK] Testing connectivity to Host Dashboard...")
    ret = os.system(f"ping -c 1 {HOST_DASHBOARD_IP} > /dev/null 2>&1")

    if ret != 0:
        print("[ERROR] Host dashboard unreachable")
    else:
        print("[OK] Host dashboard reachable ✔")


def start_forwarder():
    check_interface()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((SO_LISTEN_IP, SO_LISTEN_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("\n[*] SYSTEM OPERATOR STARTED")
    print(f"[*] Listening from SP on {SO_LISTEN_IP}:{SO_LISTEN_PORT}")
    print(f"[*] Forwarding to Host Dashboard {HOST_DASHBOARD_IP}:{HOST_DASHBOARD_PORT}")
    print("-" * 60)

    while True:
        try:
            data, addr = recv_sock.recvfrom(4096)
            recv_time = datetime.datetime.now().strftime("%H:%M:%S")

            message = json.loads(data.decode())
            msg_type = message.get("type", "UNKNOWN")

            if msg_type == "ALERT":
                print(f"\n[{recv_time}] ALERT RECEIVED")
                print(f" SM ID  : {message.get('smId')}")
                print(f" Reason : {message.get('reason')}")
            else:
                print(f"\n[{recv_time}] STATUS RECEIVED from SM {message.get('smId')}")
                print(f"Status : Normal")
                print(f"Forwarded to Host Dashboard...")

            send_sock.sendto(json.dumps(message).encode(),
                             (HOST_DASHBOARD_IP, HOST_DASHBOARD_PORT))

        except Exception as e:
            print("[ERROR]", e)


if __name__ == "__main__":
    start_forwarder()
