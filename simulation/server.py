# server.py
# heart piece of this project
# have Ids, XAI
# from REG (SM) -> to SO

import socket
import json
import time
import datetime
from collections import defaultdict

from ids_model import check_hybrid_intrusion_live


LISTEN_PORT = 9999
SO_IP = "10.0.3.2"
SO_PORT = 9999

WINDOW_SIZE = 1.0


flows = defaultdict(lambda: {
    "start_time": None,
    "last_time": None,
    "spkts": 0,
    "dpkts": 0,
    "sbytes": 0,
    "dbytes": 0,
    "jitters": []
})



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

        if len(f["jitters"]) >= 2:
            sjit = abs(f["jitters"][-1] - f["jitters"][-2])
        else:
            sjit = 0.0

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

        # Reset flow window
        flows[sm_id] = {
            "start_time": None,
            "last_time": None,
            "spkts": 0,
            "dpkts": 0,
            "sbytes": 0,
            "dbytes": 0,
            "jitters": []
        }

        return features

    return None

replay_history = defaultdict(list)

REPLAY_WINDOW = 6        
REPLAY_THRESHOLD = 5       

def detect_replay(sm_id, usage):
    history = replay_history[sm_id]
    history.append(usage)

    if len(history) > REPLAY_WINDOW:
        history.pop(0)


    if len(history) >= REPLAY_THRESHOLD and len(set(history)) == 1:
        return True

    return False


def start_server():
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.bind(("0.0.0.0", LISTEN_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("\n[*] SERVICE PROVIDER STARTED")
    print(f"[*] Listening on UDP {LISTEN_PORT}")
    print(f"[*] Forwarding to SO {SO_IP}:{SO_PORT}")
    print(f"[*] IDS Window Size: {WINDOW_SIZE}s")
    print("-" * 60)

    while True:
        try:
            data, addr = recv_sock.recvfrom(8192)
            payload = json.loads(data.decode())

            sm_id = payload.get("smId", "unknown")
            pkt_size = len(data)

            features = update_flow(sm_id, pkt_size)

            if features is None:
                continue

            now = datetime.datetime.now().strftime("%H:%M:%S")

            print(f"\n[{now}] Window closed for {sm_id}")
            print(f" spkts={features['spkts']} rate={features['rate']:.2f}")
            print(f" sload={features['sload']:.2f}")
            print(f"[DEBUG] IDS features: {features}")

            # ---- replay test----
            is_replay = detect_replay(sm_id, payload.get("usage", 0))

            isAttack, reason, score = check_hybrid_intrusion_live(features)

            
            if is_replay and features["rate"] < 20:
                isAttack = True
                reason = "Replay Attack"
                score=1.0


            if isAttack:
                print(" ATTACK DETECTED")
                print(f"   Reason: {reason}")
                print(f"   Score : {score}")

                report = {
                    "type": "ALERT",
                    "smId": sm_id,
                    "reason": reason,
                    "score": float(score),
                    "sourceIp": addr[0],
                    "timestamp": time.time(),
                    "usage": payload.get("usage", 0),
                    "status": "Stable",
                }
            else:
                print(" NORMAL")
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
