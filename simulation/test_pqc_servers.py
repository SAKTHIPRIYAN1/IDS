#!/usr/bin/env python3
"""
Simplified REG and SP servers for testing without Mininet
"""

import socket
import json
import time
import threading
from reg_node import REGNode
from sm import SmartMeter

REG_PORT = 9998
SP_PORT = 9999
REG_IP = "127.0.0.1"
SP_IP = "127.0.0.1"

def start_reg_server():
    """REG server listens for SM auth and forwards to SP"""
    reg = REGNode("REG_01")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((REG_IP, REG_PORT))
    
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print(f"[REG] Listening on {REG_IP}:{REG_PORT}")
    
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                auth_payload = json.loads(data.decode())
                message = b"AUTH_REQUEST"
                
                if reg.verify_sm(auth_payload, message):
                    kyber_ct, _ = reg.encapsulate_for_sm(auth_payload["kyber_pk"])
                    forward_msg = reg.build_forward_message(auth_payload, kyber_ct)
                    
                    send_sock.sendto(json.dumps(forward_msg).encode(), (SP_IP, SP_PORT))
                    print(f"[REG] ✓ Forwarded auth for {auth_payload['device_id']} to SP")
            except Exception as e:
                print(f"[REG] Error: {e}")
    except KeyboardInterrupt:
        print("[REG] Stopped")
        sock.close()
        send_sock.close()

def start_sp_server():
    """SP server receives auth from REG and usage from SM"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SP_IP, SP_PORT))
    
    print(f"[SP] Listening on {SP_IP}:{SP_PORT}")
    
    try:
        while True:
            data, addr = sock.recvfrom(4096)
            try:
                payload = json.loads(data.decode())
                
                if "reg_id" in payload:
                    print(f"[SP] ✓ Auth received for SM {payload['sm_id']} from REG {payload['reg_id']}")
                else:
                    print(f"[SP] ✓ Usage received from {payload.get('smId', 'unknown')}: {payload.get('usage', 0)} kWh")
            except Exception as e:
                print(f"[SP] Error: {e}")
    except KeyboardInterrupt:
        print("[SP] Stopped")
        sock.close()

if __name__ == "__main__":
    # Start servers in threads
    reg_thread = threading.Thread(target=start_reg_server, daemon=True)
    sp_thread = threading.Thread(target=start_sp_server, daemon=True)
    
    reg_thread.start()
    sp_thread.start()
    
    time.sleep(1)  # Give servers time to start
    
    # Simulate SM client
    try:
        sm = SmartMeter("SM_002")
        sm.enroll()
        sm.authenticate()
        
        auth_payload = sm.build_auth_payload(b"AUTH_REQUEST")
        
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_sock.sendto(json.dumps(auth_payload).encode(), (REG_IP, REG_PORT))
        print(f"[SM] Auth sent to REG")
        
        time.sleep(2)
        
        for i in range(3):
            payload = {
                "smId": "SM_002",
                "usage": 1.5 + i * 0.1,
                "timestamp": time.time()
            }
            client_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            print(f"[SM] Usage sent: {payload['usage']} kWh")
            time.sleep(1)
        
        client_sock.close()
        
    except KeyboardInterrupt:
        print("\n[SM] Stopped")
