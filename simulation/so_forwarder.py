# so_forwarder.py
# System Operator (SO)
# Receives STATUS / ALERT from SP
# Forwards to Host Dashboard (with XAI)
# Receives CONTROL from Web and forwards to SP

import socket
import json
import os
import threading
from crypto.so_node import SONode
from crypto.tokenmanager import TokenManager

SO_LISTEN_IP = "0.0.0.0"
SO_LISTEN_PORT = 9999          # SP → SO (alerts)

SO_CONTROL_PORT = 8899         # WEB → SO (control)

HOST_DASHBOARD_IP = "172.17.250.1"
HOST_DASHBOARD_PORT = 8888

SP_IP = "10.0.3.1"
SP_AUTH_PORT = 10999
SP_USAGE_PORT = 9999           # SO → SP (BLOCK goes here)

# ---------------- CONTROL LISTENER (WEB → SO) ----------------
def control_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", SO_CONTROL_PORT))

    print(f"[SO] Control listener active on port {SO_CONTROL_PORT}")

    while True:
        data, addr = sock.recvfrom(2048)
        cmd = json.loads(data.decode())

        action = cmd.get("action")
        sm_id = cmd.get("smId")
        reason = cmd.get("reason", "N/A")

        print("\n==============================")
        print("🚨 [SO CONTROL RECEIVED]")
        print(f"From   : {addr}")
        print(f"Action : {action}")
        print(f"SM ID  : {sm_id}")
        print(f"Reason : {reason}")
        print("==============================")

        # ---- FORWARD TO SP ----
        if action == "BLOCK":
            forward_to_sp(action, sm_id, reason)

def forward_to_sp(action, sm_id, reason):
    # Build payload
    payload = {
        "action": action,
        "sm_id": sm_id,
        "reason": reason
    }

    # Inject token into the payload
    token = TokenManager.create_token(device_id=sm_id, issuer="SO")
    payload = TokenManager.inject_token(payload, token)

    # Forward to SP
    try:
        sp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sp_sock.sendto(
            json.dumps(payload).encode(),
            (SP_IP, SP_USAGE_PORT)
        )
        sp_sock.close()

        print(f"[SO → SP] BLOCK command forwarded for {sm_id}\n")

    except Exception as e:
        print(f"[SO ERROR] Failed to forward BLOCK to SP: {e}")

# ---------------- NETWORK CHECK ----------------
def check_interface():
    print("\n[SO CHECK] Interfaces")
    os.system("ip addr show")

    print("\n[SO CHECK] Ping Web Dashboard")
    os.system(f"ping -c 1 {HOST_DASHBOARD_IP}")

# ---------------- MAIN FORWARDER ----------------
def start_forwarder():
    so = SONode("SO1", SP_IP, SP_AUTH_PORT)

    if not so.authenticate_with_sp():
        print("[SO ERROR] Authentication failed")
        return

    print("[SO] Authenticated with SP")

    check_interface()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind((SO_LISTEN_IP, SO_LISTEN_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[SO] Forwarding SP → WEB started")

    while True:
        data, _ = recv_sock.recvfrom(4096)
        message = json.loads(data.decode())

        send_sock.sendto(
            json.dumps(message).encode(),
            (HOST_DASHBOARD_IP, HOST_DASHBOARD_PORT)
        )

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    threading.Thread(target=control_listener, daemon=True).start()
    start_forwarder()
