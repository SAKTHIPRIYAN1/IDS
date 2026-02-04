# server.py
# SERVICE PROVIDER (SP)
# REG -> SP : TCP authentication
# SM  -> SP : UDP usage
# SP  -> SO : UDP report
# IDS + Replay Detection (timestamp + nonce)

import socket
import json
import time
import threading
from collections import defaultdict, deque

from crypto.sp_node import SPNode
from ids_model import check_hybrid_intrusion_live

# ---------------- CONFIG ----------------
LISTEN_PORT_USAGE = 9999
LISTEN_PORT_AUTH  = 10999

SO_IP   = "10.0.3.2"
SO_PORT = 9999

WINDOW_SIZE = 1.0

CLOCK_SKEW_TOLERANCE = 3.0      # seconds (SM ↔ SP clock drift)
NONCE_CACHE_SIZE    = 20        # per SM
REPLAY_SCORE        = 0.99

# ---------------- INIT ----------------
sp = SPNode("SP1")
authenticated_sms = {}   # sm_id → auth log

# ---------------- REPLAY STATE ----------------
# sm_id → deque of (nonce, ts_bucket)
replay_cache = defaultdict(lambda: deque(maxlen=NONCE_CACHE_SIZE))

# ---------------- FLOW STATE ----------------
flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "spkts": 0,
    "sbytes": 0,
    "jitters": []
})

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
        rate  = f["spkts"] / dur if dur > 0 else 0
        sload = f["sbytes"] / dur if dur > 0 else 0
        sjit  = abs(f["jitters"][-1] - f["jitters"][-2]) if len(f["jitters"]) >= 2 else 0.0

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

# ---------------- REPLAY DETECTION ----------------
def detect_replay(sm_id, timestamp, nonce):
    now = time.time()

    # ---- freshness check (clock skew tolerant) ----
    if abs(now - timestamp) > CLOCK_SKEW_TOLERANCE:
        return True, "Stale timestamp"

    ts_bucket = int(timestamp)
    key = (nonce, ts_bucket)

    # ---- nonce reuse ----
    if key in replay_cache[sm_id]:
        return True, "Nonce replay detected"

    replay_cache[sm_id].append(key)
    return False, None

# ---------------- AUTH HANDLER ----------------
def handle_auth_from_reg():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT_AUTH))
    sock.listen(5)

    print("[SP] Auth listener active")

    while True:
        conn, _ = sock.accept()
        try:
            payload = json.loads(conn.recv(16384).decode())
            log_entry = sp.handle_reg_message(payload)

            authenticated_sms[log_entry["sm_id"]] = log_entry
            print(f"[SP] AUTH SUCCESS → {log_entry['sm_id']}")

        except Exception as e:
            print("[SP AUTH ERROR]", e)
        finally:
            conn.close()

# ---------------- MAIN ----------------
def start_server():
    threading.Thread(target=handle_auth_from_reg, daemon=True).start()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(("0.0.0.0", LISTEN_PORT_USAGE))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("[SP] Usage listener active")

    while True:
        try:
            data, _ = recv_sock.recvfrom(8192)
            payload = json.loads(data.decode())

            sm_id     = payload.get("smId")
            usage     = payload.get("usage", 0)
            timestamp = payload.get("timestamp", 0)
            nonce     = payload.get("nonce")

            if sm_id not in authenticated_sms:
                print(f"[SP WARNING] Unauthenticated SM {sm_id}")
                print(f"[SP ACTION] Traffic ignored (fail-closed)")

                continue
    
    

            # ---------- REPLAY DETECTION ----------
            replay, reason = detect_replay(sm_id, timestamp, nonce)
            if replay:
                alert = {
                    "smId": sm_id,
                    "status": "Unstable",
                    "type": "ALERT",
                    "usage":usage,
                    "reason": reason,
                    "score": REPLAY_SCORE,
                    "xai": f"Replay detected via {reason}"
                }

                send_sock.sendto(json.dumps(alert).encode(), (SO_IP, SO_PORT))
                print(f"[REPLAY] {sm_id} → {reason}")
                continue

            # ---------- IDS ----------
            features = update_flow(sm_id, len(data))
            if not features:
                continue

            isAttack, reason, score, xai, _ = check_hybrid_intrusion_live(features)

            final_score = max(score, REPLAY_SCORE if replay else 0)

            report = {
                "smId": sm_id,
                "usage": usage,
                "status": "Unstable" if isAttack else "Stable",
                "reason": reason,
                "score": float(final_score),
                "xai": xai,
                "type": "ALERT" if isAttack else "NORMAL"
            }

            send_sock.sendto(json.dumps(report).encode(), (SO_IP, SO_PORT))
            print(f"[SP → SO] Report sent for {sm_id}")

        except Exception as e:
            print("[SP ERROR]", e)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    start_server()
