# so_forwarder.py
# System Operator (SO)
# Receives STATUS / ALERT from Service Provider (SP)
# Forwards to Host Dashboard

import socket
import json
import os
import datetime

# ---------------- CONFIG ----------------
SO_LISTEN_IP = "0.0.0.0"
SO_LISTEN_PORT = 9999

HOST_DASHBOARD_IP = "192.168.250.1"
HOST_DASHBOARD_PORT = 8888


# ---------------- INTERFACE CHECK ----------------
def check_interface():
    print("\n[CHECK] Listing SO network interfaces:")
    os.system("ip addr show")

    print("\n[CHECK] Testing connectivity to Host Dashboard...")
    ret = os.system(f"ping -c 1 {HOST_DASHBOARD_IP} > /dev/null 2>&1")

    if ret != 0:
        print("[ERROR] Host dashboard unreachable")
        print("  - Check veth pair")
        print("  - Check routing")
        print("  - Check HOST_DASHBOARD_IP")
    else:
        print("[OK] Host dashboard reachable ✔")


# ---------------- MAIN ----------------
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

            try:
                message = json.loads(data.decode())
            except json.JSONDecodeError:
                print("[!] Invalid JSON received — dropped")
                continue

            msg_type = message.get("type", "UNKNOWN")

            if msg_type == "ALERT":
                print(f"\n[{recv_time}] ALERT RECEIVED")
                print(f"    SM ID     : {message.get('smId')}")
                print(f"    Reason    : {message.get('reason')}")
                print(f"    Score     : {message.get('score')}")
                print(f"    Source IP : {message.get('sourceIp')}")

            elif msg_type == "STATUS":
                print(f"\n[{recv_time}] STATUS RECEIVED")
                print(f"    SM ID     : {message.get('smId')}")
                print(f"    Usage     : {message.get('usage')} kWh")

            else:
                print(f"\n[{recv_time}] ℹ Unknown message type")

            # Forward to host dashboard
            send_sock.sendto(data, (HOST_DASHBOARD_IP, HOST_DASHBOARD_PORT))
            print("    Forwarded → Host Dashboard")

        except Exception as e:
            print("[ERROR]", e)


if __name__ == "__main__":
    start_forwarder()
