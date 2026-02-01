import socket
import json
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto.reg_node import REGNode

# REG listens on port 9998 for SM auth
LISTEN_PORT = 9998
SP_IP = "10.0.3.1"
SP_AUTH_PORT = 10999  # SP auth port for large payloads
SP_USAGE_PORT = 9999   # SP usage port for UDP

def start_reg_server(reg_id):
    reg = REGNode(reg_id)

    # TCP socket for auth (large payload)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", LISTEN_PORT))
    tcp_sock.listen(1)

    # TCP socket for forwarding auth to SP
    sp_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f"[REG {reg_id}] Listening on TCP port {LISTEN_PORT}")

    try:
        while True:
            conn, addr = tcp_sock.accept()
            print(f"[REG {reg_id}] Received connection from {addr}")

            try:
                data = conn.recv(16384)  # Receive up to 16KB
                auth_payload = json.loads(data.decode())
                message = b"AUTH_REQUEST"

                if reg.verify_sm(auth_payload, message):
                    kyber_ct, shared_secret = reg.encapsulate_for_sm(auth_payload["kyber_pk"])

                    forward_msg = reg.build_forward_message(auth_payload, kyber_ct)

                    # Forward to SP via TCP (large auth payload)
                    try:
                        sp_tcp_sock.connect((SP_IP, SP_AUTH_PORT))
                        sp_tcp_sock.sendall(json.dumps(forward_msg).encode())
                        sp_tcp_sock.close()
                        sp_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        print(f"[REG {reg_id}] Forwarded auth for {auth_payload['device_id']} to SP via TCP")
                    except Exception as e:
                        print(f"[REG {reg_id}] Error forwarding to SP: {e}")

            except Exception as e:
                print(f"[REG {reg_id}] Error: {e}")
            finally:
                conn.close()

    except KeyboardInterrupt:
        print(f"[REG {reg_id}] Stopped")
        tcp_sock.close()
        sp_tcp_sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python reg_server.py <reg_id>")
        sys.exit(1)

    reg_id = sys.argv[1]
    start_reg_server(reg_id)