from flask import Flask, render_template_string
import socket
import threading
import json
import datetime

# -------------------------
# CONFIGURATION
# -------------------------
UDP_IP = '0.0.0.0'
UDP_PORT = 8888
WEB_PORT = 8080

app = Flask(__name__)

# Shared list to store incoming grid/IDS updates
grid_data = []

# -------------------------
# 1) UDP LISTENER THREAD
# -------------------------
def udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))
    print(f"[*] Dashboard UDP listener running on {UDP_IP}:{UDP_PORT}")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            report = json.loads(data.decode())

            # Auto add timestamp
            report["time"] = datetime.datetime.now().strftime("%H:%M:%S")

            # Keep last 30 rows max
            grid_data.insert(0, report)
            if len(grid_data) > 30:
                grid_data.pop()

        except Exception as e:
            print("[!] UDP receive error:", e)

# -------------------------
# 2) Web Dashboard (HTML)
# -------------------------
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Q-BLAISE - Live System Operator Dashboard</title>
    <meta http-equiv="refresh" content="2">
    <style>
        body { 
            font-family: Arial; 
            background: #f5f5f5; 
            padding: 20px; 
        }
        h1 { color: #333; }
        table {
            width: 100%; 
            border-collapse: collapse;
            background: white;
            box-shadow: 0px 0px 8px #ccc;
        }
        th {
            background: #1976d2;
            color: white;
            padding: 10px;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #ddd;
        }
        tr:nth-child(even) { background: #f0f0f0; }

        .OK { color: green; font-weight: bold; }
        .ALERT { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>⚡ Q-BLAISE: System Operator Dashboard</h1>
    <h3>Live Grid Events (Auto-updates every 2 sec)</h3>

    <table>
        <tr>
            <th>Time</th>
            <th>Type</th>
            <th>Source IP</th>
            <th>Meter ID</th>
            <th>Usage</th>
            <th>Status</th>
        </tr>

        {% for row in data %}
        <tr>
            <td>{{ row.time }}</td>
            <td>{{ row.type }}</td>
            <td>{{ row.source_ip }}</td>
            <td>{{ row.sm_id }}</td>
            <td>{{ row.usage }}</td>
            <td class="{{ row.status }}">{{ row.status }}</td>
        </tr>
        {% endfor %}
    </table>

</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE, data=grid_data)

# -------------------------
# MAIN START
# -------------------------
if __name__ == "__main__":
    # Start UDP listener
    t = threading.Thread(target=udp_listener)
    t.daemon = True
    t.start()

    # Start dashboard
    print(f"[*] Web Dashboard available at http://0.0.0.0:{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
