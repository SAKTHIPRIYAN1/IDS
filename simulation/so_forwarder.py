import socket
import json
import os

# conFiggg!!


# SO listens to SP traffic (inside Mininet subnet)
SO_LISTEN_IP = "0.0.0.0"
SO_LISTEN_PORT = 9999   # SP port

# Host UDP
HOST_DASHBOARD_IP = "192.168.250.1"
HOST_DASHBOARD_PORT = 8888


# checking the config
def check_interface():
    print("\n[CHECK] Listing all SO interfaces:")
    os.system("ip addr show")

    print("\n[CHECK] Testing connectivity to Host Dashboard...")
    ret = os.system(f"ping -c 1 {HOST_DASHBOARD_IP} > /dev/null 2>&1")

    if ret != 0:
        print("[ERROR] Host dashboard is unreachable!")
        print("Possible causes:")
        print("  - veth-mn not configured")
        print("  - veth-host not configured")
        print("  - Wrong HOST_DASHBOARD_IP")
        print("  - Routing problem")
    else:
        print("[OK] Host dashboard is reachable ✔")

check_interface()

print(f"[*] SO Forwarder: Listening on {SO_LISTEN_IP}:{SO_LISTEN_PORT}")
print(f"[*] Forwarding all packets to HOST on http://127.0.0.1:8080/")


# SOCKETS
recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
recv_sock.bind((SO_LISTEN_IP, SO_LISTEN_PORT))

send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)




while True:
    try:
        data, addr = recv_sock.recvfrom(4096)

        # Validate JSON
        try:
            json.loads(data.decode())
        except json.JSONDecodeError:
            print("[!] Invalid JSON received, skipping")
            continue

        # Forward to host dashboard
        send_sock.sendto(data, (HOST_DASHBOARD_IP, HOST_DASHBOARD_PORT))
        print(f"[+] Forwarded packet from SP ({addr}) → HOST Dashboard")

    except Exception as e:
        print("[!] Error:", e)
