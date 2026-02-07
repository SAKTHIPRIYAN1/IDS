# Mininet Simulation: PQC-Integrated Smart Grid IDS

## Quick Start (5 Steps)

### Step 1: Start Docker Container
```bash
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim
```

### Step 2: Launch Mininet Topology
```bash
cd /simulation
python3 runTopo.py
```

Expected output:
```
*** Starting network...
*** Adding hosts and switches
[...]
*** All servers started. Use CLI to interact.
*** Starting CLI:
mininet>
```

### Step 3: Run Smart Meters (from Mininet CLI)
```bash
# Terminal 1: SM1-5 (connected to REG1)
mininet> sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
mininet> sm2 python3 client.py SM_002 > /tmp/sm2.log 2>&1 &
mininet> sm3 python3 client.py SM_003 > /tmp/sm3.log 2>&1 &

# Terminal 2: SM6-10 (connected to REG2)
mininet> sm6 python3 client.py SM_006 > /tmp/sm6.log 2>&1 &
mininet> sm7 python3 client.py SM_007 > /tmp/sm7.log 2>&1 &
```

### Step 4: Monitor Output
```bash
# Still in Mininet CLI:
mininet> sp tail -f /tmp/sp.log
mininet> reg1 tail -f /tmp/reg1.log
mininet> so tail -f /tmp/so.log

# Or check logs after simulation:
mininet> sh tail -f /tmp/sm1.log
```

### Step 5: Simulate Attack (Optional)
```bash
# In Mininet CLI, run replay attack on SM1:
mininet> sm1 python3 attacks/replay.py SM_001
```

---

## Detailed Network Topology

```
┌─────────────────────────────────────────────────────────┐
│                   MININET TOPOLOGY                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  REG1 (10.0.1.254)              REG2 (10.0.2.254)     │
│  │                               │                     │
│  ├─ RegS1                        ├─ RegS2             │
│  │  ├─ SM1 (10.0.1.1)            │  ├─ SM6 (10.0.2.1) │
│  │  ├─ SM2 (10.0.1.2)            │  ├─ SM7 (10.0.2.2) │
│  │  ├─ SM3 (10.0.1.3)            │  └─ ...            │
│  │  ├─ SM4 (10.0.1.4)                                 │
│  │  └─ SM5 (10.0.1.5)            SP (10.0.3.1)        │
│  │                                │                    │
│  └───────────────────────────────→│ TCP:10999 (auth)   │
│                                   │                    │
│                                   SO (10.0.3.2)        │
│                                   │                    │
│                                   └─ UDP:9999 (usage)  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Key Port Mappings

| Component | Listen Port | Protocol | Purpose |
|-----------|------------|----------|---------|
| REG1/REG2 | 9998 | TCP | Receive auth from SM |
| SP | 10999 | TCP | Receive auth from REG |
| SP | 9999 | UDP | Receive usage from SM |
| SO | 9999 | UDP | Receive alerts from SP |

---

## Full Command Sequence (Copy-Paste Ready)

### Terminal 1: Start Mininet
```bash
cd /simulation
python3 runTopo.py
```

### Terminal 2: Monitor Servers (inside Mininet, but in separate shell)
```bash
# After Mininet starts, from host:
docker exec -it <container_id> bash
cd /simulation

# Monitor each server
tail -f /tmp/reg1.log &
tail -f /tmp/sp.log &
tail -f /tmp/so.log &
tail -f /tmp/sm1.log &
```

### Inside Mininet CLI: Start Everything

**Start REGs + SP + SO** (already done by runTopo.py):
```bash
# Just verify they're running:
mininet> ps aux | grep python
```

**Start Smart Meters** (one at a time, or use screen/tmux):
```bash
# Batch 1: REG1 SMs
mininet> sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
mininet> sm2 python3 client.py SM_002 > /tmp/sm2.log 2>&1 &
mininet> sm3 python3 client.py SM_003 > /tmp/sm3.log 2>&1 &
mininet> sm4 python3 client.py SM_004 > /tmp/sm4.log 2>&1 &
mininet> sm5 python3 client.py SM_005 > /tmp/sm5.log 2>&1 &

# Batch 2: REG2 SMs
mininet> sm6 python3 client.py SM_006 > /tmp/sm6.log 2>&1 &
mininet> sm7 python3 client.py SM_007 > /tmp/sm7.log 2>&1 &
mininet> sm8 python3 client.py SM_008 > /tmp/sm8.log 2>&1 &
mininet> sm9 python3 client.py SM_009 > /tmp/sm9.log 2>&1 &
mininet> sm10 python3 client.py SM_010 > /tmp/sm10.log 2>&1 &
```

**Check flows** (after 10-15 seconds):
```bash
mininet> sp cat /tmp/sp.log | grep "✓\|ALERT"
mininet> so cat /tmp/so.log | grep "received\|STATUS"
```

---

## Expected Output

### SP Log (`/tmp/sp.log`)
```
*** SERVICE PROVIDER STARTED
*** Listening on UDP 9999 (usage) and TCP 10999 (auth)
*** Forwarding to SO 10.0.3.2:9999
────────────────────────────────────────────────────────────
[SP] Auth listener on TCP port 10999
[SP] ✓ Auth received for SM SM_001 from REG reg1
[SP] ✓ Usage received from SM_001: 2.3 kWh
[SP] ✓ Usage received from SM_001: 1.8 kWh
[SP] ALERT: ANOMALY DETECTED in SM_001 (usage spike)
[SP] ✓ Auth received for SM SM_006 from REG reg2
[SP] ✓ Usage received from SM_006: 3.1 kWh
```

### REG1 Log (`/tmp/reg1.log`)
```
[REG reg1] Listening on TCP port 9998
[REG reg1] Received connection from ('10.0.1.1', 53451)
[REG reg1] Received 12966 bytes from ('10.0.1.1', 53451)
[REG reg1] ✅ SM signature verified
[REG reg1] ML-KEM encapsulation completed
[REG reg1] ✓ Forwarded auth for SM_001 to SP via TCP
[REG reg1] Received connection from ('10.0.1.2', 53452)
```

### SO Log (`/tmp/so.log`)
```
[*] SYSTEM OPERATOR STARTED
[*] Listening from SP on 0.0.0.0:9999
[*] Forwarding to Host Dashboard 172.17.250.1:8888
────────────────────────────────────────────────────────────
Received STATUS from SM_001: Stable
Received ALERT from SM_001: Unstable (DoS detected)
Received STATUS from SM_006: Stable
```

### SM1 Log (`/tmp/sm1.log`)
```
[*] Smart Meter SM_001 started
[ENROLL] Device SM_001 enrolled
[AUTH] Device SM_001 auth success: True
[SM] Keys generated & stored in memory
[SM → REG] Auth sent to 10.0.1.254:9998
[SM → SP] usage=2.3 kWh
[SM → SP] usage=1.8 kWh
[SM → SP] usage=3.5 kWh
```

---

## Simulate Attacks

### 1. Replay Attack on SM1
```bash
mininet> sm1 python3 attacks/replay.py SM_001 &
```
Expected: IDS detects repeated identical usage values → ALERT

### 2. DoS Attack on SM2
```bash
mininet> sm2 python3 attacks/dos.py SM_002 &
```
Expected: SP detects abnormal packet rate → ALERT

### 3. Burst Attack on SM3
```bash
mininet> sm3 python3 attacks/burst.py SM_003 &
```
Expected: IDS detects usage spike → ALERT

---

## Monitor Real-Time

### Option A: Inside Mininet CLI
```bash
mininet> sp tail -100f /tmp/sp.log
mininet> so tail -100f /tmp/so.log
```

### Option B: From Host (in another terminal)
```bash
docker exec -it <container_id> bash -c "tail -f /tmp/sp.log"
```

### Option C: Grep for Alerts
```bash
mininet> sp grep ALERT /tmp/sp.log
mininet> so grep ALERT /tmp/so.log
```

---

## Stop Everything

```bash
# Inside Mininet CLI:
mininet> net.stop()  # or Ctrl+D
```

Or cleanly:
```bash
mininet> sh killall python3
mininet> exit
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| "Connection refused" on REG | Ensure REG servers started (check `ps aux`) |
| SP doesn't receive auth | Verify REG → SP TCP:10999 connection (check routing) |
| SO doesn't receive alerts | Check UDP:9999 open on SO, SP can reach 10.0.3.2 |
| SMs timeout | Ensure default route `via 10.0.x.254` is set (see myTopo.py) |
| "No module named 'crypto'" | Check `sys.path.insert()` in client.py, reg_server.py, server.py |
| Mininet hangs | Kill stray processes: `pkill -f python3` |

---

## Advanced: Run with Attack Scenarios

### Scenario 1: 3 Normal + 2 Replay
```bash
# Normal SMs
mininet> sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
mininet> sm2 python3 client.py SM_002 > /tmp/sm2.log 2>&1 &
mininet> sm3 python3 client.py SM_003 > /tmp/sm3.log 2>&1 &

# Under attack
mininet> sm4 python3 attacks/replay.py SM_004 > /tmp/sm4.log 2>&1 &
mininet> sm5 python3 attacks/replay.py SM_005 > /tmp/sm5.log 2>&1 &

# Monitor
mininet> sp tail -f /tmp/sp.log | grep "ALERT\|Stable\|Unstable"
```

### Scenario 2: Measure PQC Overhead
```bash
# Time SM authentication
mininet> sm1 time python3 -c "from crypto.sm import SmartMeter; sm = SmartMeter('SM_001'); sm.enroll(); sm.authenticate(); auth = sm.build_auth_payload(b'AUTH_REQUEST'); print(len(json.dumps(auth)))"
```

Expected: ~12KB JSON, ~100-200ms auth time

---

## Performance Metrics to Collect

1. **Auth Latency**: REG receives SM auth → REG forwards to SP
   ```bash
   grep "Received" /tmp/reg1.log | head -1
   grep "Forwarded" /tmp/reg1.log | head -1
   # Calculate delta
   ```

2. **Usage Throughput**: Count messages/second from SMs
   ```bash
   wc -l /tmp/sp.log | awk '{print $1 / 30}' # msgs per 30 sec
   ```

3. **IDS Decision Time**: Time from usage received to alert/status sent
   ```bash
   grep "Usage received" /tmp/sp.log | tail -1
   grep "ALERT\|STATUS" /tmp/so.log | tail -1
   ```

---

## One-Liner Quick Test

```bash
# 1. Start Mininet
python3 runTopo.py > /tmp/mininet.log 2>&1 &
sleep 3

# 2. Exec commands into running container
docker exec ids-pqc-sim bash -c "
  cd /simulation && \
  mininet -c sm1 python3 client.py SM_001 &
  mininet -c sp tail -f /tmp/sp.log
"
```

---

## Summary

**To run the complete PQC-integrated IDS with Mininet:**

1. `docker run --entrypoint bash -it --privileged --net host ids-pqc-sim`
2. `cd /simulation && python3 runTopo.py`
3. In Mininet: `sm1 python3 client.py SM_001 &` (repeat for other SMs)
4. `sp tail -f /tmp/sp.log` (monitor alerts)
5. Optional: `sm1 python3 attacks/replay.py SM_001 &` (trigger attack)

That's it! The PQC auth handshake, IDS checks, and alert forwarding all run automatically.

