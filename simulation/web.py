from flask import Flask, render_template_string, redirect, url_for
import socket, threading, json, datetime, time

# --- CONFIGURATION ---
UDP_IP = "0.0.0.0"
UDP_PORT = 8888
WEB_PORT = 8080
INACTIVE_TIMEOUT = 10

SO_CONTROL_IP = "172.17.250.2"   # SO container IP (veth)
SO_CONTROL_PORT = 8899


app = Flask(__name__)

# --- DATA STORES ---
events = []
active_alerts = {}      
cleared_alerts = set()
last_seen = {}          
is_expanded = []  # List to track expanded states on server side


def send_control(action, smId, reason):
    msg = {
        "action": action,
        "smId": smId,
        "reason": reason,
        "timestamp": time.time()
    }
    print(f"[WEB] Sending control command: {msg}")  # Debug print
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(json.dumps(msg).encode(), (SO_CONTROL_IP, SO_CONTROL_PORT))
        print(f"[WEB] Control command sent to SO at {SO_CONTROL_IP}:{SO_CONTROL_PORT}")
    except Exception as e:
        print(f"[WEB ERROR] Failed to send control command: {e}")
    finally:
        sock.close()


# --- UDP LISTENER (BACKEND) ---
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"[*] Dashboard UDP listener on {UDP_IP}:{UDP_PORT}")

    while True:
        try:
            data, _ = sock.recvfrom(4096)
            msg = json.loads(data.decode())

            now = datetime.datetime.now()
            now_str = now.strftime("%H:%M:%S")

            sm = msg.get("smId", "-")
            score = float(msg.get("score", 0))
            reason = msg.get("reason", "Unknown")
            xai_exp = msg.get("xai", "-")

            is_attack = msg.get("type") == "ALERT" or score > 75
            
            if not is_attack:
                reason = "-"
                score = "-"

            last_seen[sm] = now

            # ---- ALERT STATE MACHINE ----
            if is_attack:
                if sm not in active_alerts:
                    # New Alert
                    active_alerts[sm] = {
                        "smId": sm,
                        "reason": reason,
                        "from": now_str,
                        "to": now_str,
                        "score": score,
                        "Xai_exp": xai_exp
                    }
                    cleared_alerts.discard(sm)
                else:
                    # Update Existing Alert
                    active_alerts[sm]["to"] = now_str
                    active_alerts[sm]["score"] = score
                    if xai_exp != "-":
                        active_alerts[sm]["Xai_exp"] = xai_exp
            else:
                # If node returns to normal, remove alert
                active_alerts.pop(sm, None)

            # Add to Event Log
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

            # Keep log size small
            if len(events) > 50:
                events.pop()
        except Exception as e:
            print(f"Error processing packet: {e}")

# --- CLEANUP THREAD ---
def cleanup_inactive():
    while True:
        time.sleep(1)
        now = datetime.datetime.now()
        # Find nodes inactive for > 10 seconds
        inactive_sms = [
            sm for sm, ts in last_seen.items()
            if (now - ts).total_seconds() > INACTIVE_TIMEOUT
        ]
        for sm in inactive_sms:
            last_seen.pop(sm, None)
            active_alerts.pop(sm, None)
            if sm in is_expanded:
                is_expanded.remove(sm) # Cleanup expanded state too

# --- FRONTEND HTML TEMPLATE ---
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>System Operator</title>
<meta http-equiv="refresh" content="2">

<style>
body {
    margin:0;
    font-family:Segoe UI,sans-serif;
    background:radial-gradient(circle at top,#1b2735,#090a0f);
    color:#eee;
}
h1 { text-align:center; margin:15px; color:#fff; }

.container {
    display:flex;
    flex-direction:column;
    height:calc(100vh - 80px);
    padding:20px;
    gap:15px;
}
.top { display:flex; gap:15px; height:45%; }
.bottom { height:55%; }

.glass {
    background:rgba(255,255,255,0.07);
    backdrop-filter:blur(14px);
    border-radius:14px;
    padding:15px;
    border:1px solid rgba(255,255,255,0.12);
    display:flex;
    flex-direction:column;
    overflow:hidden;
}

.panel-header {
    font-size:1.1em;
    border-bottom:1px solid rgba(255,255,255,0.15);
    padding-bottom:6px;
    margin-bottom:10px;
    font-weight:bold;
}

.scroll { overflow-y:auto; flex:1; padding-right:5px; }
.scroll::-webkit-scrollbar { width: 8px; }
.scroll::-webkit-scrollbar-track { background: rgba(0,0,0,0.1); }
.scroll::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.2); border-radius: 4px; }

/* Metrics */
.metrics {
    display:flex;
    justify-content:space-between;
    align-items:center;
    height:100%;
}

.metric {
    width:26%;
    border-radius:10px;
    padding:15px;
    text-align:center;
    background:rgba(255,255,255,0.06);
}

.metric .val { font-size:2.2em; font-weight:bold; margin-bottom:5px; }
.metric.active { color:#4caf50; }
.metric.risky  { color:#ff5252; }
.metric.normal { color:#2196f3; }

/* Alerts */
.alert-box {
    background:rgba(255,82,82,0.15);
    border-left:4px solid #ff5252;
    padding:10px;
    margin-bottom:10px;
    position:relative;
}
.dismiss {
    position:absolute; top:5px; right:8px;
    color:#ff5252; text-decoration:none; font-weight:bold; font-size:1.2em;
}

/* Table */
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:rgba(0,0,0,0.3); padding:10px; text-transform:uppercase; color:#aaa; }
td { padding:8px; text-align:center; border-bottom:1px solid rgba(255,255,255,0.05); }

/* --- ROW COLORS --- */
tr.ALERT { background:rgba(255,82,82,0.2); }
/* CHANGED: Added green background for normal status logs */
tr.STATUS { background:rgba(76, 175, 80, 0.2); color: #e8f5e9; }

/* Expand Button */
.expand-btn {
    margin-top: 8px;
    background: none;
    border: none;
    color: #2196f3;
    cursor: pointer;
    font-size: 0.9em;
    font-weight: bold;
    text-transform: uppercase;
    padding: 0;
}
.expand-btn:hover { text-decoration: underline; color: #64b5f6; }

.xai-exp {
    margin-top: 10px;
    padding: 10px;
    background: rgba(0,0,0,0.3);
    border-radius: 6px;
    font-size: 0.9em;
    color: #e3f2fd;
    border-left: 2px solid #2196f3;
}
</style>

<script>
function toggleXaiExp(id, smId) {
    const exp = document.getElementById(id);
    // Note: We use the fetch API to tell server to remember the state
    if (exp.style.display === "none" || exp.style.display === "") {
        exp.style.display = "block";
        fetch(`/expand/${smId}`);
    } else {
        exp.style.display = "none";
        fetch(`/collapse/${smId}`);
    }
}
</script>
</head>

<body>
<h1>System Operator – Live Grid & IDS Monitor</h1>

<div class="container">

<div class="top">

<div class="glass alert-panel" style="flex:1.4">
<div class="panel-header" style="color:#ff5252">Active Alerts</div>
<div class="scroll">
{% if alerts|length == 0 %}
    <div style="text-align:center; color:#aaa; padding:20px;">System Secure. No Active Threats.</div>
{% endif %}

{% for a in alerts %}
<div class="alert-box">
    <a class="dismiss" href="/clear/{{ a.smId }}" title="Dismiss Alert">✖</a>
    <b>{{ a.smId }} COMPROMISED</b><br>
    Reason: {{ a.reason }}<br>
    Time: {{ a.from }} → {{ a.to }}<br>
    Score: <b>{{ a.score }}</b>
    <br>
    <button class="expand-btn" onclick="toggleXaiExp('xai-{{ a.smId }}', '{{ a.smId }}')">
        Details & XAI Explanation ▼
    </button>
    
    <div id="xai-{{ a.smId }}" class="xai-exp" 
         style="display: {% if a.smId in is_expanded %}block{% else %}none{% endif %};">
        <b>XAI Analysis:</b><br>
        {{ a.Xai_exp | safe }}
    </div>
    

</div>
{% endfor %}
</div>
</div>

<div class="glass metric-panel" style="flex:1">
<div class="panel-header metric-header">System Metrics</div>
<div class="metrics">
    <div class="metric active">
        <div class="val">{{ active }}</div>
        Active Nodes
    </div>
    <div class="metric risky">
        <div class="val">{{ risky }}</div>
        Under Attack
    </div>
    <div class="metric normal">
        <div class="val">{{ normal }}</div>
        Secure
    </div>
</div>
</div>

</div>

<div class="glass bottom log-panel">
<div class="panel-header">Complete Event Log</div>
<div class="scroll">
<table>
<tr>
<th>Time</th><th>Type</th><th>SM</th>
<th>Usage</th><th>Status</th><th>Reason</th>
</tr>
{% for e in data %}
<tr class="{{ e.type }}">
<td>{{ e.time }}</td>
<td>{{ e.type }}</td>
<td>{{ e.smId }}</td>
<td>{{ e.usage }}</td>
<td>{{ e.status }}</td>
<td>{{ e.reason }}</td>
</tr>
{% endfor %}
</table>
</div>
</div>

</div>
</body>
</html>
"""

# --- ROUTES ---

@app.route("/")
def index():
    active_nodes_set = set(last_seen.keys())
    all_alerts_set = set(active_alerts.keys())
    
    risky_nodes_set = all_alerts_set.intersection(active_nodes_set)
    
    active_count = len(active_nodes_set)
    risky_count = len(risky_nodes_set)
    normal_count = active_count - risky_count

    return render_template_string(
        HTML,
        data=events,
        alerts=list(active_alerts.values()),
        active=active_count,
        risky=risky_count,
        normal=normal_count,
        is_expanded=is_expanded
    )

@app.route("/expand/<sm>")
def expand(sm):
    if sm not in is_expanded:
        is_expanded.append(sm)
    return "", 204

@app.route("/collapse/<sm>")
def collapse(sm):
    if sm in is_expanded:
        is_expanded.remove(sm)
    return "", 204

@app.route("/clear/<sm>")
def clear(sm):
    active_alerts.pop(sm, None)
    cleared_alerts.add(sm)
    return redirect(url_for("index"))



@app.route("/action/<action>/<sm>")
def take_action(action, sm):
    alert = active_alerts.get(sm)
    reason = alert["reason"] if alert else "Unknown"

    send_control(action.upper(), sm, reason)
    return redirect(url_for("index"))

# ---------------- MAIN ----------------
if __name__ == "__main__":
    threading.Thread(target=udp_listener, daemon=True).start()
    threading.Thread(target=cleanup_inactive, daemon=True).start()

    print(f"[*] Web running on port {WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)