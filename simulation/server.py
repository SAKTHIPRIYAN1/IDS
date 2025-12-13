
# this is the file for service provider
# recieve data from Sm through reg
# send to the SO

import socket
import json
import datetime

# CONFIGURATION
LISTEN_PORT = 9999
SO_IP = '10.0.3.2'  # SO address
SO_PORT = 9999


def start_server():
# reciv
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(('0.0.0.0', LISTEN_PORT))

# sending
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(f"[*] SP SERVER Running.")
    print(f"[*] Receiving from Meters on Port {LISTEN_PORT}")
    print(f"[*] Forwarding to SO at {SO_IP}:{SO_PORT}")
    print("-" * 50)

    while True:
        try:
            # Receive from Smart Meter
            data, addr = receiver.recvfrom(4096)
            payload = json.loads(data.decode())
            
            # --- Simulation!!! ---

            
            report = {
                "type": "STATUS",  
                "smId": payload.get("smId"),
                "usage": payload.get("usage"),
                "status": "Stable",
                "sourceIp": addr[0]
            }

            # Forward to System Operator
            message = json.dumps(report).encode()
            sender.sendto(message, (SO_IP, SO_PORT))
            
            print(f"[+] Processed data from {payload.get('smId')} -> Sent to SO.")

        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    start_server()