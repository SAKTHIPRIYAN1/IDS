#!/usr/bin/env python3
"""
Simplified REG and SP servers for testing without Mininet
"""

import socket
import json
import time
import threading

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from reg_node import REGNode
from sm import SmartMeter

REG_PORT = 9998
SP_PORT = 9999
REG_IP = "127.0.0.1"
SP_IP = "127.0.0.1"

def start_reg_server():
    """REG server listens for SM auth via TCP and forwards to SP via TCP"""
    reg = REGNode("REG_01")
    
    # TCP socket for auth (large payload)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((REG_IP, REG_PORT))
    tcp_sock.listen(1)
    
    # TCP socket for forwarding to SP (auth message also large)
    sp_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"[REG] Listening on TCP {REG_IP}:{REG_PORT}")
    
    try:
        while True:
            conn, addr = tcp_sock.accept()
            try:
                data = conn.recv(16384)  # Receive up to 16KB
                if data:
                    print(f"[REG] Received {len(data)} bytes from {addr}")
                    auth_payload = json.loads(data.decode())
                    message = b"AUTH_REQUEST"
                    
                    if reg.verify_sm(auth_payload, message):
                        kyber_ct, _ = reg.encapsulate_for_sm(auth_payload["kyber_pk"])
                        forward_msg = reg.build_forward_message(auth_payload, kyber_ct)
                        
                        # Forward to SP via TCP (auth message is large)
                        try:
                            sp_tcp_sock.connect((SP_IP, SP_PORT + 1000))  # SP auth port = 10999
                            sp_tcp_sock.sendall(json.dumps(forward_msg).encode())
                            sp_tcp_sock.close()
                            sp_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            print(f"[REG] ✓ Forwarded auth for {auth_payload['device_id']} to SP via TCP")
                        except Exception as e:
                            print(f"[REG] Error forwarding to SP: {e}")
                    else:
                        print(f"[REG] ❌ Auth verification failed")
            except Exception as e:
                print(f"[REG] Error: {e}")
            finally:
                conn.close()
    except KeyboardInterrupt:
        print("[REG] Stopped")
        tcp_sock.close()
        sp_tcp_sock.close()

def start_sp_server():
    """SP server receives auth from REG via TCP and usage from SM via UDP"""
    # TCP socket for auth from REG (large payload)
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_sock.bind((SP_IP, SP_PORT + 1000))  # Auth port = 10999
    tcp_sock.listen(1)
    
    # UDP socket for usage from SM (small payload)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.bind((SP_IP, SP_PORT))
    
    print(f"[SP] Listening on TCP {SP_IP}:{SP_PORT + 1000} (auth) and UDP {SP_IP}:{SP_PORT} (usage)")
    
    def handle_tcp():
        """Accept auth messages from REG"""
        try:
            while True:
                conn, addr = tcp_sock.accept()
                try:
                    data = conn.recv(16384)
                    if data:
                        payload = json.loads(data.decode())
                        if "reg_id" in payload:
                            print(f"[SP] ✓ Auth received for SM {payload['sm_id']} from REG {payload['reg_id']}")
                except Exception as e:
                    print(f"[SP] Auth error: {e}")
                finally:
                    conn.close()
        except KeyboardInterrupt:
            tcp_sock.close()
    
    def handle_udp():
        """Handle usage messages from SM"""
        try:
            while True:
                data, addr = udp_sock.recvfrom(4096)
                try:
                    payload = json.loads(data.decode())
                    if "smId" in payload:
                        print(f"[SP] ✓ Usage received from {payload.get('smId', 'unknown')}: {payload.get('usage', 0)} kWh")
                except Exception as e:
                    print(f"[SP] Usage error: {e}")
        except KeyboardInterrupt:
            udp_sock.close()
    
    # Run both in parallel
    tcp_thread = threading.Thread(target=handle_tcp, daemon=True)
    udp_thread = threading.Thread(target=handle_udp, daemon=True)
    
    tcp_thread.start()
    udp_thread.start()
    
    # Keep threads alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[SP] Stopped")
        tcp_sock.close()
        udp_sock.close()

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
        
        # Debug: print payload structure and sizes
        print(f"[SM] Auth payload keys: {list(auth_payload.keys())}")
        print(f"[SM] Payload sizes - device_id: {len(auth_payload['device_id'])}, kyber_pk: {len(auth_payload['kyber_pk'])}, dilithium_pk: {len(auth_payload['dilithium_pk'])}, signature: {len(auth_payload['signature'])}")
        
        auth_json = json.dumps(auth_payload)
        print(f"[SM] Auth JSON size: {len(auth_json)} bytes")
        
        # Use TCP for large auth payload
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_sock.connect((REG_IP, REG_PORT))
        tcp_sock.sendall(auth_json.encode())
        tcp_sock.close()
        print(f"[SM] Auth sent to REG via TCP")
        
        time.sleep(2)
        
        # Use UDP for smaller usage messages
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for i in range(3):
            payload = {
                "smId": "SM_002",
                "usage": 1.5 + i * 0.1,
                "timestamp": time.time()
            }
            udp_sock.sendto(json.dumps(payload).encode(), (SP_IP, SP_PORT))
            print(f"[SM] Usage sent: {payload['usage']} kWh")
            time.sleep(1)
        
        udp_sock.close()
        
    except KeyboardInterrupt:
        print("\n[SM] Stopped")
