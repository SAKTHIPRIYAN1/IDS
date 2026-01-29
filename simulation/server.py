# server.py
# SERVICE PROVIDER (REG + SM -> IDS -> SO)
# PQC-enabled auth from REG, usage from SM, IDS checks, forward to SO

import socket
import json
import time
import datetime
import threading
from collections import defaultdict

from ids_model import check_hybrid_intrusion_live

LISTEN_PORT_USAGE = 9999      # UDP: SM usage messages
LISTEN_PORT_AUTH = 10999      # TCP: REG auth messages
SO_IP = "10.0.3.2"
SO_PORT = 9999

WINDOW_SIZE = 1.0

# -------- AUTH STATE --------
authenticated_devices = {}  # {device_id: auth_data}

# ---------------- FLOW STATE ----------------
flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "spkts": 0,
    "sbytes": 0,
    "jitters": []
})

# ---------------- REPLAY STATE ----------------
replay_history = defaultdict(list)
REPLAY_WINDOW = 6
REPLAY_THRESHOLD = 5

# ---------------- FLOW UPDATE ----------------
def update_flow(sm_id, pkt_size):
    now = time.time()
    f = flows[sm_id]

    if f["start_time"] is None:
        f["start_time"] = now
        f["last_time"] = now

    delta = now - f["last_time"]

    f["spkts"] += 1
    f["sbytes"] += pkt_size

    if delta > 0:
        f["jitters"].append(delta)

    f["last_time"] = now
    dur = now - f["start_time"]

    if dur >= WINDOW_SIZE:
        rate = f["spkts"] / dur if dur > 0 else 0
        sload = f["sbytes"] / dur if dur > 0 else 0
        sjit = abs(f["jitters"][-1] - f["jitters"][-2]) if len(f["jitters"]) >= 2 else 0.0

        features = {
            "dur": dur,
            "proto": "udp",
            "service": "-",
            "state": "INT",
            "spkts": f["spkts"],
            "dpkts": 0,
            "sbytes": f["sbytes"],
            "dbytes": 0,
            "rate": rate,
            "sload": sload,
            "sjit": sjit
        }

        flows[sm_id] = {
            "start_time": None,
            "last_time": None,
            "spkts": 0,
            "sbytes": 0,
            "jitters": []
        }

        return features

    return None

# -------- AUTH HANDLER (TCP) --------
def handle_auth_from_reg():
    """Listen on TCP 10999 for auth from REG"""
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind(("0.0.0.0", LISTEN_PORT_AUTH))
    tcp_sock.listen(1)
    
    print(f"[SP] Auth listener on TCP port {LISTEN_PORT_AUTH}")
    
    try:
        while True:
            conn, addr = tcp_sock.accept()
            try:
                data = conn.recv(16384)
                if data:
                    auth_msg = json.loads(data.decode())
                    sm_id = auth_msg.get("sm_id")
                    
                    # Store auth data for this device
                    authenticated_devices[sm_id] = {
                        "timestamp": time.time(),
                        "kyber_ct": auth_msg.get("kyber_ct"),
                        "signature": auth_msg.get("signature"),
                        "reg_id": auth_msg.get("reg_id")
                    }
                    
                    print(f"[SP] ✓ Auth received for SM {sm_id} from REG {auth_msg.get('reg_id')}")
            except Exception as e:
                print(f"[SP] Auth error: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        tcp_sock.close()

# ---------- REPLAY DETECTION ----------
def detect_replay(sm_id, usage):
    history = replay_history[sm_id]
    history.append(usage)

    if len(history) > REPLAY_WINDOW:
        history.pop(0)

    return len(history) >= REPLAY_THRESHOLD and len(set(history)) == 1

# ---------- SERVER ----------
def start_server():
    # Start auth listener in separate thread
    auth_thread = threading.Thread(target=handle_auth_from_reg, daemon=True)
    auth_thread.start()
    
    # Usage listener (UDP)
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(("0.0.0.0", LISTEN_PORT_USAGE))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("\n[*] SERVICE PROVIDER STARTED")
    print(f"[*] Listening on UDP {LISTEN_PORT_USAGE} (usage) and TCP {LISTEN_PORT_AUTH} (auth)")
    print(f"[*] Forwarding to SO {SO_IP}:{SO_PORT}")
    print("-" * 60)

    while True:
        try:
            data, addr = recv_sock.recvfrom(8192)
            payload = json.loads(data.decode())

            sm_id = payload.get("smId") or payload.get("sm_id", "unknown")
            pkt_size = len(data)

            # If auth payload from REG, log and skip IDS
            if "reg_id" in payload:
                print(f"[SP] Auth received for {sm_id} from REG {payload['reg_id']}")
                continue

            features = update_flow(sm_id, pkt_size)
            if not features:
                continue

            now = datetime.datetime.now().strftime("%H:%M:%S")

            print(f"\n[{now}] Window closed for {sm_id}")
            print(f"[DEBUG] IDS features: {features}")

            # Replay check (rule-based)
            if detect_replay(sm_id, payload.get("usage", 0)):
                report = {
                    "type": "ALERT",
                    "smId": sm_id,
                    "reason": "Rule-based Replay Detection",
                    "xai": "Repeated identical packet usage observed across time windows",
                    "score": 1.0,
                    "sourceIp": addr[0],
                    "usage": payload.get("usage", 0),
                    "status": "Unstable"
                }

            else:
                # ML-based IDS
                isAttack, model_reason, score, xai_exp, _ = \
                    check_hybrid_intrusion_live(features)

                if isAttack:
                    report = {
                        "type": "ALERT",
                        "smId": sm_id,
                        "reason": model_reason,
                        "xai": xai_exp,
                        "score": float(score),
                        "sourceIp": addr[0],
                        "usage": payload.get("usage", 0),
                        "status": "Unstable"
                    }
                else:
                    report = {
                        "type": "STATUS",
                        "smId": sm_id,
                        "usage": payload.get("usage", 0),
                        "status": "Stable",
                        "sourceIp": addr[0]
                    }

            send_sock.sendto(json.dumps(report).encode(), (SO_IP, SO_PORT))
            print(" → Forwarded to SO")

        except Exception as e:
            print("[ERROR]", e)

if __name__ == "__main__":
    start_server()
