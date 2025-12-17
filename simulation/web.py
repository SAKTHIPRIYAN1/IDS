# dashboard.py
# Dark Glassmorphic System Operator Dashboard

from flask import Flask, render_template_string
import socket
import threading
import json
import datetime

# -------------------------
# CONFIG
# -------------------------
UDP_IP = "0.0.0.0"
UDP_PORT = 8888
WEB_PORT = 8080

app = Flask(__name__)

events = []   # ring buffer


# -------------------------
# UDP LISTENER
# -------------------------
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    print(f"[*] Dashboard UDP listener on {UDP_IP}:{UDP_PORT}")

    while True:
        data, _ = sock.recvfrom(4096)
        msg = json.loads(data.decode())

        entry = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "type": msg.get("type", "STATUS"),
            "smId": msg.get("smId", "-"),
            "sourceIp": msg.get("sourceIp", "-"),
            "usage": msg.get("usage", "-"),
            "status": msg.get("status", "-"),
            "reason": msg.get("reason", "-"),
            "score": msg.get("score", "-"),
        }

        events.insert(0, entry)
        if len(events) > 50:
            events.pop()


# -------------------------
# UI
# -------------------------
HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-BLAISE | SO Dashboard</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body {
            margin: 0;
            font-family: 'Segoe UI', sans-serif;
            background: radial-gradient(circle at top, #1b2735, #090a0f);
            color: #eee;
        }

        h1 {
            text-align: center;
            margin: 15px 0;
            font-weight: 400;
            letter-spacing: 1px;
        }

        /* ---------- Glass Card ---------- */
        .glass {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border-radius: 16px;
            border: 1px solid rgba(255,255,255,0.15);
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        }

        /* ---------- Layout ---------- */
        .container {
            display: flex;
            flex-direction: column;
            height: 100vh;
            padding: 15px;
            gap: 15px;
        }

        .top {
            flex: 0 0 40%;
            display: flex;
            gap: 15px;
        }

        .bottom {
            flex: 1;
            overflow: hidden;
        }

        /* ---------- Status Panels ---------- */
        .panel {
            flex: 1;
            padding: 20px;
        }

        .panel h2 {
            margin-top: 0;
            font-weight: 400;
        }

        .alert {
            color: #ff5252;
            text-shadow: 0 0 10px rgba(255,82,82,0.6);
        }

        .status {
            color: #4caf50;
            text-shadow: 0 0 10px rgba(76,175,80,0.6);
        }

        .event {
            padding: 8px;
            margin: 6px 0;
            border-radius: 8px;
            font-size: 14px;
        }

        .ALERT {
            background: rgba(255, 82, 82, 0.15);
            border-left: 4px solid #ff5252;
        }

        .STATUS {
            background: rgba(76, 175, 80, 0.15);
            border-left: 4px solid #4caf50;
        }

        /* ---------- Table ---------- */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            background: rgba(0,0,0,0.4);
            padding: 10px;
        }

        td {
            padding: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            text-align: center;
        }

        tr.ALERT td { color: #ff8a80; }
        tr.STATUS td { color: #a5d6a7; }

    </style>
</head>
<body>

<h1>System Operator – Live Grid & IDS Monitor</h1>

<div class="container">

    <!-- UPPER HALF -->
    <div class="top">
        <div class="panel glass">
            <h2 class="alert">🚨 Active Alerts</h2>
            {% for e in data if e.type == 'ALERT' %}
            <div class="event ALERT">
                <b>{{ e.time }}</b> | {{ e.smId }} | {{ e.reason }} | Score: {{ e.score }}
            </div>
            {% endfor %}
        </div>

        <div class="panel glass">
            <h2 class="status">✅ System Status</h2>
            {% for e in data if e.type == 'STATUS' %}
            <div class="event STATUS">
                <b>{{ e.time }}</b> | {{ e.smId }} | Usage: {{ e.usage }}
            </div>
            {% endfor %}
        </div>
    </div>

    <!-- LOWER HALF -->
    <div class="bottom glass" style="padding:15px; overflow-y:auto;">
        <h2>📜 Event Log (From SO)</h2>
        <table>
            <tr>
                <th>Time</th><th>Type</th><th>SM</th><th>IP</th>
                <th>Usage</th><th>Status</th><th>Reason</th><th>Score</th>
            </tr>
            {% for e in data %}
            <tr class="{{ e.type }}">
                <td>{{ e.time }}</td>
                <td>{{ e.type }}</td>
                <td>{{ e.smId }}</td>
                <td>{{ e.sourceIp }}</td>
                <td>{{ e.usage }}</td>
                <td>{{ e.status }}</td>
                <td>{{ e.reason }}</td>
                <td>{{ e.score }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

</div>

</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML, data=events)


# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    t = threading.Thread(target=udp_listener, daemon=True)
    t.start()

    print(f"[*] Dashboard running at http://0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
