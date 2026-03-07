# reg_server.py
import socket
import json
import sys
import os
import hashlib
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto.reg_node import REGNode
from crypto.sp_node import SPNode

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

LISTEN_PORT = 9998
SP_IP = "10.0.3.1"
SP_AUTH_PORT = 10999

# ---------------- BLOCKLIST ----------------
blocklist = set()

# ---------------- REG SERVER ----------------
def start_reg_server(reg_id):
    logging.debug(f"[REG_SERVER][INIT] Starting REG server with reg_id: {reg_id}")
    reg = REGNode(reg_id)

    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", LISTEN_PORT))
    tcp_sock.listen(5)

    logging.debug(f"[REG_SERVER][INIT] REG server listening on TCP port {LISTEN_PORT}")
    print(f"[REG {reg_id}] Listening on TCP {LISTEN_PORT}")

    while True:
        conn, addr = tcp_sock.accept()
        reg_ip = addr[0]  # REG IP as seen by SP
        logging.debug(f"[REG_SERVER][CONNECTION] Connection received from {addr}")

        try:
            data = conn.recv(16384)
            payload = json.loads(data.decode())
            logging.debug(f"[REG_SERVER][PAYLOAD_RECEIVED] Received payload: {json.dumps(payload, indent=4)}")

            # ---------------- BLOCK COMMAND ----------------
            if payload.get("action") == "BLOCK":
                sm_id = payload.get("smId")
                logging.debug(f"[REG_SERVER][BLOCK] Blocking SM with sm_id: {sm_id}")
                blocklist.add(sm_id)
                logging.debug(f"[REG_SERVER][BLOCK] SM {sm_id} added to blocklist")
                print(f"[REG] SM {sm_id} BLOCKED by SP")
                conn.close()
                continue

            # ---------------- BLOCK ENFORCEMENT ----------------
            sm_id = payload.get("device_id")
            if sm_id in blocklist:
                logging.debug(f"[REG_SERVER][BLOCK_ENFORCEMENT] Blocked SM {sm_id} attempted to connect — rejected")
                print(f"[REG] Blocked SM {sm_id} attempted to connect — rejected")
                conn.close()
                continue

            # ---------------- AUTH PROCESS ----------------
            message = b"AUTH_REQUEST"
            logging.debug("[REG_SERVER][AUTH] Verifying SM authentication")
            if not reg.verify_sm(payload, message):
                logging.debug("[REG_SERVER][AUTH] SM verification FAILED")
                print("[REG] SM verification FAILED")
                conn.close()
                continue
            logging.debug("[REG_SERVER][AUTH] SM verification SUCCESS")

            # ---- PUF derivation ----
            logging.debug("[REG_SERVER][PUF_DERIVATION] Deriving SK_PUF")
            sk_puf, _ = reg.derive_sk_puf(message)
            logging.debug(f"[REG_SERVER][PUF_DERIVATION] Derived SK_PUF: {sk_puf.hex()}")

            # ---- Generate M2 ----
            logging.debug("[REG_SERVER][M2_GENERATION] Generating M2")
            m2 = hashlib.sha256((payload["device_id"] + reg_id).encode()).digest()
            logging.debug(f"[REG_SERVER][M2_GENERATION] Generated M2: {m2.hex()}")

            # ---- Sign M2 ----
            logging.debug("[REG_SERVER][SIGN_M2] Signing M2")
            sigma_reg, sk_puf_hash = reg.sign_m2(sk_puf, m2)
            logging.debug(f"[REG_SERVER][SIGN_M2] Generated sigma_reg (HMAC): {sigma_reg.hex()}")
            logging.debug(f"[REG_SERVER][SIGN_M2] Generated SK_PUF hash: {sk_puf_hash.hex()}")

            # ---- SP Kyber public key ----
            logging.debug("[REG_SERVER][KYBER_ENCAPSULATION] Retrieving SP Kyber public key")
            sp = SPNode("SP1")
            ct_reg, _ = reg.encapsulate_for_sp(sp.kyber_pk.hex())
            logging.debug(f"[REG_SERVER][KYBER_ENCAPSULATION] Generated ciphertext (C_REG): {ct_reg.hex()}")

            # ---- Build message to SP ----
            logging.debug("[REG_SERVER][BUILD_MESSAGE] Building message to SP")
            forward_msg = reg.build_message_to_sp(
                sm_id=payload["device_id"],
                m2=m2,
                sigma_reg=sigma_reg,
                ct_reg=ct_reg,
                sk_puf_hash=sk_puf_hash,
                reg_id=reg_id,
                reg_ip=reg_ip
            )
            logging.debug(f"[REG_SERVER][BUILD_MESSAGE] Built message to SP: {json.dumps(forward_msg, indent=4)}")

            # ---- Send to SP ----
            logging.debug("[REG_SERVER][FORWARD_TO_SP] Forwarding authentication message to SP")
            sp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sp_sock.connect((SP_IP, SP_AUTH_PORT))
            sp_sock.sendall(json.dumps(forward_msg).encode())
            sp_sock.close()
            logging.debug("[REG_SERVER][FORWARD_TO_SP] Authentication message forwarded to SP")
            print(f"[REG → SP] Auth forwarded for SM {payload['device_id']}")

        except Exception as e:
            logging.error(f"[REG_SERVER][ERROR] {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 reg_server.py REG1")
        sys.exit(1)

    start_reg_server(sys.argv[1])
