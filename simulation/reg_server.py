import socket
import json
import sys
from puf.reg_node import REGNode

# REG listens on port 9998 for SM auth
LISTEN_PORT = 9998
SP_IP = "10.0.3.1"
SP_PORT = 9999

def start_reg_server(reg_id):
    reg = REGNode(reg_id)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[REG {reg_id}] Listening on port {LISTEN_PORT}")

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            print(f"[REG {reg_id}] Received from {addr}")

            try:
                auth_payload = json.loads(data.decode())
                message = b"AUTH_REQUEST"

                if reg.verify_sm(auth_payload, auth_payload["signature"]):
                    kyber_ct, shared_secret = reg.encapsulate_for_sm(auth_payload["kyber_pk"])

                    forward_msg = reg.build_forward_message(auth_payload, kyber_ct)

                    # Forward to SP
                    send_sock.sendto(json.dumps(forward_msg).encode(), (SP_IP, SP_PORT))
                    print(f"[REG {reg_id}] Forwarded auth for {auth_payload['device_id']} to SP")

            except Exception as e:
                print(f"[REG {reg_id}] Error: {e}")

    except KeyboardInterrupt:
        print(f"[REG {reg_id}] Stopped")
        sock.close()
        send_sock.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python reg_server.py <reg_id>")
        sys.exit(1)

    reg_id = sys.argv[1]
    start_reg_server(reg_id)