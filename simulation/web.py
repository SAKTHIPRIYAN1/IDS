# dashboard.py
# Dark Glassmorphic System Operator Dashboard (Metrics + Alerts, NO GLOBE)

from flask import Flask, render_template_string, redirect, url_for
import socket, threading, json, datetime, time

# -------------------------
# CONFIG
# -------------------------
UDP_IP = "0.0.0.0"
UDP_PORT = 8888
WEB_PORT = 8080
INACTIVE_TIMEOUT = 5  # seconds

app = Flask(__name__)

events = []
active_alerts = {}      # smId -> alert info
cleared_alerts = set()
last_seen = {}          # smId -> timestamp

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

        now = datetime.datetime.now()
        now_str = now.strftime("%H:%M:%S")

        sm = msg.get("smId", "-")
        score = float(msg.get("score", 0))
        reason = msg.get("reason", "Unknown")

        is_attack = msg.get("type") == "ALERT" or score > 75
        if not is_attack:
            reason = "-"
            score = "-"

        last_seen[sm] = now

        # ---- ALERT STATE MACHINE ----
        if is_attack:
            if sm not in active_alerts:
                active_alerts[sm] = {
                    "smId": sm,
                    "reason": reason,
                    "from": now_str,
                    "to": now_str,
                    "score": score
                }
                cleared_alerts.discard(sm)
            else:
                active_alerts[sm]["to"] = now_str
                active_alerts[sm]["score"] = score
        else:
            active_alerts.pop(sm, None)

        # ---- EVENT LOG ----
        events.insert(0, {
            "time": now_str,
            "type": msg.get("type", "STATUS"),
            "smId": sm,
            "sourceIp": msg.get("sourceIp", "-"),
            "usage": msg.get("usage", "-"),
            "status": msg.get("status", "-"),
            "reason": reason,
            "score": score,
        })

        if len(events) > 50:
            events.pop()


# -------------------------
# CLEANUP THREAD (INACTIVE SMs)
# -------------------------
def cleanup_inactive():
    while True:
        time.sleep(1)
        now = datetime.datetime.now()
        inactive_sms = [
            sm for sm, ts in last_seen.items()
            if (now - ts).total_seconds() > INACTIVE_TIMEOUT
        ]
        for sm in inactive_sms:
            last_seen.pop(sm, None)
            active_alerts.pop(sm, None)


# -------------------------
# UI
# -------------------------
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Q-BLAISE | System Operator</title>
<meta http-equiv="refresh" content="2">

<style>
body {
    margin:0;
    font-family:Segoe UI,sans-serif;
    background:radial-gradient(circle at top,#1b2735,#090a0f);
    color:#eee;
}
h1 { text-align:center; margin:15px; }

.container {
    display:flex;
    flex-direction:column;
    height:calc(100vh - 80px);
    padding:20px;
    gap:15px;
}
.top { display:flex; gap:15px; height:40%; }
.bottom { height:60%; }

.glass {
    background:rgba(255,255,255,0.07);
    backdrop-filter:blur(14px);
    border-radius:14px;
    padding:15px;
    border:1px solid rgba(255,255,255,0.12);
    transition:border 0.3s;
    display:flex;
    flex-direction:column;
    overflow:hidden;
}

/* Hover Borders 
# .alert-panel:hover  { border:1px solid #ff5252; }
# .metric-panel:hover { border:1px solid #4caf50; }
# .log-panel:hover    { border:1px solid #2196f3; }*/

.panel-header {
    font-size:1.1em;
    border-bottom:1px solid rgba(255,255,255,0.15);
    padding-bottom:6px;
    margin-bottom:10px;
}

.scroll { overflow-y:auto; flex:1; }

/* Metrics */
.metrics {
    display:flex;
    justify-content:center;
    gap:20px;
}

.metric {
    width:140px;
    border-radius:10px;
    padding:15px;
    text-align:center;
    background:rgba(255,255,255,0.06);
}

.metric .val { font-size:2em; font-weight:bold; }

.metric.active { color:#4caf50; }
.metric.risky  { color:#ff5252; }
.metric.normal { color:#2196f3; }

.metric-header { color:#4caf50; }

/* Alerts */
.alert-box {
    background:rgba(255,82,82,0.15);
    border-left:4px solid #ff5252;
    padding:10px;
    margin-bottom:8px;
    position:relative;
}
.dismiss {
    position:absolute;
    top:5px;
    right:8px;
    color:#ff5252;
    text-decoration:none;
    font-weight:bold;
}

/* Table */
table {
    width:100%;
    border-collapse:collapse;
    font-size:13px;
}
th { background:#1b2735; padding:8px; }
td { padding:6px; text-align:center; }

tr.ALERT { background:rgba(255,82,82,0.2); }
tr.STATUS { background:rgba(76,175,80,0.2); }

table tr td {
    padding:8px;
}

table tr {
    border-bottom:2px solid rgba(255,255,255,0.1);
}

</style>
</head>

<body>
<h1>System Operator – Live Grid & IDS Monitor</h1>

<div class="container">

<div class="top">

<div class="glass alert-panel" style="flex:1.3">
<div class="panel-header" style="color:#ff5252">Active Alerts</div>
<div class="scroll">
{% for a in alerts %}
<div class="alert-box">
<a class="dismiss" href="/clear/{{ a.smId }}">✖</a>
<b>{{ a.smId }} COMPROMISED</b><br>
Reason: {{ a.reason }}<br>
From {{ a.from }} → {{ a.to }}<br>
Score: {{ a.score }}
</div>
{% endfor %}
</div>
</div>

<div class="glass metric-panel" style="flex:1">
<div class="panel-header metric-header">System Metrics</div>

<div class="metrics">
<div class="metric active"><div class="val">{{ active }}</div>Active Nodes</div>
<div class="metric risky"><div class="val">{{ risky }}</div>Risky Nodes</div>
<div class="metric normal"><div class="val">{{ normal }}</div>Normal Nodes</div>
</div>
</div>

</div>

<div class="glass bottom log-panel">
<div class="panel-header">Complete Event Log</div>
<div class="scroll">
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

</div>
</body>
</html>
"""

# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def index():
    active_nodes = set(last_seen.keys())
    risky_nodes = set(active_alerts.keys())

    return render_template_string(
        HTML,
        data=events,
        alerts=active_alerts.values(),
        active=len(active_nodes),
        risky=len(risky_nodes),
        normal=max(0, len(active_nodes) - len(risky_nodes))
    )

@app.route("/clear/<sm>")
def clear(sm):
    active_alerts.pop(sm, None)
    cleared_alerts.add(sm)
    return redirect(url_for("index"))

# -------------------------
# MAIN
# -------------------------
if __name__ == "__main__":
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=cleanup_inactive, daemon=True).start()
    print(f"[*] Dashboard running at http://0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
