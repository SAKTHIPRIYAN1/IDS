#!/bin/bash

# Start Open vSwitch
service openvswitch-switch start

echo "[+] Open vSwitch started"

# Required for Mininet
sysctl -w net.ipv4.ip_forward=1

echo "[+] IP forwarding enabled"

# Drop into shell (so you can run Mininet manually)
exec bash
