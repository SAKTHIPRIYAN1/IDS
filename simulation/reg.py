# reg_server.py
import socket
import json
import sys
import os
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto.reg_node import REGNode

LISTEN_PORT = 9998
SP_IP = "10.0.3.1"
SP_AUTH_PORT = 10999

# ---------------- BLOCKLIST ----------------
blocklist = set()

# ---------------- REG SERVER ----------------
def start_reg_server(reg_id):
    reg = REGNode(reg_id)

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", LISTEN_PORT))
    tcp_sock.listen(5)

    print(f"[REG {reg_id}] Listening on TCP {LISTEN_PORT}")

    while True:
        conn, addr = tcp_sock.accept()
        reg_ip = addr[0]   # 🔥 REG IP as seen by SP
        print(f"[REG] Connection from {addr}")

        try:
            data = conn.recv(16384)
            payload = json.loads(data.decode())

            # ---------------- BLOCK COMMAND ----------------
            if payload.get("action") == "BLOCK":
                sm_id = payload.get("smId")
                blocklist.add(sm_id)
                print(f"[REG] SM {sm_id} BLOCKED by SP")
                conn.close()
                continue

            # ---------------- BLOCK ENFORCEMENT ----------------
            sm_id = payload.get("device_id")
            if sm_id in blocklist:
                print(f"[REG] Blocked SM {sm_id} attempted to connect — rejected")
                conn.close()
                continue

            # ---------------- AUTH PROCESS ----------------
            message = b"AUTH_REQUEST"

            if not reg.verify_sm(payload, message):
                print("[REG] SM verification FAILED")
                conn.close()
                continue

            # ---- PUF derivation ----
            sk_puf, _ = reg.derive_sk_puf(message)

            m2 = hashlib.sha256(
                (payload["device_id"] + reg_id).encode()
            ).digest()

            sigma_reg, sk_puf_hash = reg.sign_m2(sk_puf, m2)

            # ---- SP Kyber public key ----
            from crypto.sp_node import SPNode
            sp = SPNode("SP1")

            ct_reg, _ = reg.encapsulate_for_sp(sp.kyber_pk.hex())

            # ---- Build message to SP ----
            forward_msg = reg.build_message_to_sp(
                sm_id=payload["device_id"],
                m2=m2,
                sigma_reg=sigma_reg,
                ct_reg=ct_reg,
                sk_puf_hash=sk_puf_hash,
                reg_id=reg_id,
                reg_ip=reg_ip
            )

            #  CRITICAL ADDITIONS
            forward_msg["reg_id"] = reg_id
            forward_msg["reg_ip"] = reg_ip

            # ---- Send to SP ----
            sp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sp_sock.connect((SP_IP, SP_AUTH_PORT))
            sp_sock.sendall(json.dumps(forward_msg).encode())
            sp_sock.close()

            print(f"[REG → SP] Auth forwarded for SM {payload['device_id']}")

        except Exception as e:
            print(f"[REG ERROR] {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 reg_server.py REG1")
        sys.exit(1)

    start_reg_server(sys.argv[1])
