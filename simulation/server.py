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
import oqs

# ---------------- CONFIG ----------------
LISTEN_PORT_USAGE = 9999
LISTEN_PORT_AUTH  = 10999
REG_PORT = 9998

SO_IP   = "10.0.3.2"
SO_PORT = 9999

WINDOW_SIZE = 1.0  # Time window for flow analysis (in seconds)
CLOCK_SKEW_TOLERANCE = 3.0  # seconds (SM ↔ SP clock drift)
NONCE_CACHE_SIZE = 20  # Max number of nonces to store per SM
REPLAY_SCORE = 0.99
REPLAY_WINDOW = 5.0  # Time window (in seconds) to check for duplicate packets

# ---------------- INIT ----------------
sp = SPNode("SP1")
authenticated_sms = {}  # sm_id → auth log

# ---------------- REPLAY STATE ----------------
# sm_id → deque of (nonce, ts_bucket)
replay_cache = defaultdict(lambda: deque(maxlen=NONCE_CACHE_SIZE))

# sm_id → deque of (usage, timestamp) for replay detection
packet_cache = defaultdict(lambda: deque())

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
def detect_replay(sm_id, timestamp, nonce, usage):
    now = time.time()

    # ---- freshness check (clock skew tolerant) ----
    if abs(now - timestamp) > CLOCK_SKEW_TOLERANCE:
        return True, "Stale timestamp"

    # ---- nonce reuse (only if nonce is provided) ----
    if nonce is not None:
        ts_bucket = int(timestamp)
        key = (nonce, ts_bucket)

        if key in replay_cache[sm_id]:
            return True, "Nonce replay detected"

        replay_cache[sm_id].append(key)

    # ---- packet replay detection ----
    # Check if the exact same packet (sm_id, usage, timestamp) was received recently
    for cached_packet in packet_cache[sm_id]:
        cached_usage, cached_timestamp = cached_packet
        # Only flag as replay if both usage and timestamp are exactly the same
        if cached_usage == usage and cached_timestamp == timestamp:
            return True, "Identical packet replay detected"

    # Add the current packet to the cache
    packet_cache[sm_id].append((usage, timestamp))

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
            data = conn.recv(16384)
            print(f"[SP DEBUG] Raw data received: {data}")  # Debug print
            payload = json.loads(data.decode())
            print(f"[SP DEBUG] Decoded payload: {payload}")  # Debug print

            # Check if the request is from an SO
            if "so_id" in payload:
                print(f"[SP] Received SO authentication request from {payload['so_id']}")
                handle_so_auth(conn, payload)
            elif "sm_id" in payload:
                # Handle SM authentication
                sm_id = payload["sm_id"]
                timestamp = payload.get("timestamp", int(time.time()))
                log_entry = sp.handle_reg_message(payload)
                authenticated_sms[log_entry["sm_id"]] = log_entry
                print(f"[SP] AUTH SUCCESS → {log_entry['sm_id']}")
                conn.sendall(json.dumps({"status": "AUTH_SUCCESS"}).encode())

                # Log the successful SM authentication to activity.json
                sm_log_entry = {
                    "event": "SM_AUTH_SUCCESS",  # Specify the event type
                    "sm_id": sm_id,
                    "timestamp": timestamp,
                    "status": "AUTH_SUCCESS"
                }
                log_auth_activity(sm_log_entry)
            else:
                print("[SP AUTH ERROR] Invalid authentication payload")
                conn.sendall(json.dumps({"status": "AUTH_FAILED", "error": "Invalid payload"}).encode())

        except Exception as e:
            print("[SP AUTH ERROR]", e)
            conn.sendall(json.dumps({"status": "AUTH_FAILED", "error": str(e)}).encode())
        finally:
            conn.close()

# ---------------- SO AUTH HANDLER ----------------
import json
import os

# File to store activity logs
ACTIVITY_LOG_FILE = "activity.json"

def handle_so_auth(conn, payload):
    try:
        so_id = payload["so_id"]
        kyber_pk = payload["kyber_pk"]
        dilithium_pk = payload["dilithium_pk"]
        signature = bytes.fromhex(payload["signature"])
        timestamp = payload["timestamp"]

        # Ensure dilithium_pk is a string
        if not isinstance(dilithium_pk, str):
            raise ValueError("dilithium_pk must be a hexadecimal string")

        # Verify the signature
        message = b"AUTH_REQUEST"
        with oqs.Signature("ML-DSA-65") as verifier:
            is_valid = verifier.verify(
                message,
                signature,
                bytes.fromhex(dilithium_pk)
            )

        if not is_valid:
            print(f"[SP] SO {so_id} authentication FAILED")
            conn.sendall(json.dumps({"status": "AUTH_FAILED"}).encode())
            return

        print(f"[SP] SO {so_id} authentication SUCCESS")
        conn.sendall(json.dumps({"status": "AUTH_SUCCESS"}).encode())

        # Log the successful authentication to activity.json
        log_entry = {
            "event": "SO_AUTH_SUCCESS",  # Specify the event type
            "so_id": so_id,
            "timestamp": timestamp,
            "status": "AUTH_SUCCESS"
        }
        log_auth_activity(log_entry)

    except Exception as e:
        print(f"[SP ERROR] Failed to handle SO authentication: {e}")
        conn.sendall(json.dumps({"status": "AUTH_FAILED", "error": str(e)}).encode())
    finally:
        conn.close()

# ---------------- BLOCK HANDLER ----------------
def handle_block_command(sm_id, reason):
    activity_log = {
        "smId": sm_id,
        "action": "BLOCK",
        "reason": reason,
        "timestamp": time.time()
    }

    try:
        with open("activity.json", "a") as f:
            f.write(json.dumps(activity_log) + "\n")
        print(f"[SP] Block activity logged for SM {sm_id}")  # Debug print
    except Exception as e:
        print(f"[SP ERROR] Failed to log block activity: {e}")

    # Forward the block command to REG
    reg_ip = authenticated_sms.get(sm_id, {}).get("reg_ip")
    print(authenticated_sms.get(sm_id, {}))  # Debug print to check reg_ip retrieval
    if reg_ip:
        block_command = {
            "action": "BLOCK",
            "smId": sm_id,
            "reason": reason
        }
        
        try:
            reg_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reg_sock.connect((reg_ip, REG_PORT))
            reg_sock.sendall(json.dumps(block_command).encode())
            reg_sock.close()
            print(f"[SP → REG] Block command sent for SM {sm_id}")  # Debug print
        except Exception as e:
            print(f"[SP ERROR] Failed to send block command to REG: {e}")
    else:
        print(f"[SP ERROR] REG IP not found for SM {sm_id}")

# ---------------- AUTH ACTIVITY LOGGING ----------------
def log_auth_activity(log_entry):
    """
    Logs the authentication activity to activity.json.
    """
    try:
        # Check if the file exists
        if not os.path.exists(ACTIVITY_LOG_FILE):
            with open(ACTIVITY_LOG_FILE, "w") as f:
                json.dump([], f)

        # Read the existing logs
        with open(ACTIVITY_LOG_FILE, "r") as f:
            logs = json.load(f)

        # Append the new log entry
        logs.append(log_entry)

        # Write the updated logs back to the file
        with open(ACTIVITY_LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)

        print(f"[SP] Authentication log saved: {log_entry}")

    except Exception as e:
        print(f"[SP ERROR] Failed to log authentication activity: {e}")

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

            action = payload.get("action")
            if action == "BLOCK":
                sm_id = payload.get("smId")
                reason = payload.get("reason")
                print(f"[SP] Received BLOCK command for SM {sm_id} with reason: {reason}")  # Debug print
                handle_block_command(sm_id, reason)
                continue

            sm_id     = payload.get("smId")
            usage     = payload.get("usage", 0)
            timestamp = payload.get("timestamp", 0)
            nonce     = payload.get("nonce", None)  # Default to None if nonce is not provided

            if sm_id not in authenticated_sms:
                print(f"[SP WARNING] Unauthenticated SM {sm_id}")
                print(f"[SP ACTION] Traffic ignored (fail-closed)")

                continue

            # ---------- REPLAY DETECTION ----------
            replay, reason = detect_replay(sm_id, timestamp, nonce, usage)
            if replay:
                alert = {
                    "smId": sm_id,
                    "status": "Unstable",
                    "type": "ALERT",
                    "usage": usage,
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

            status_str = "ALERT" if isAttack else "NORMAL"
            send_sock.sendto(json.dumps(report).encode(), (SO_IP, SO_PORT))
            print(f"[SP → SO] Report sent for {sm_id}: {status_str}")

        except Exception as e:
            print("[SP ERROR]", e)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    start_server()
