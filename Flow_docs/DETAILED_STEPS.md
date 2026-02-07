# Complete Mininet Simulation: Step-by-Step

## The Process Overview

```
┌─────────────┐
│ Start Docker│
└──────┬──────┘
       │
       ▼
┌──────────────────┐
│ python3 runTopo.py
│ (Start Mininet)  │
└──────┬───────────┘
       │
       ▼
    ┌──────────────────────────────────────┐
    │     Mininet CLI: mininet>            │
    └──────────────────────────────────────┘
       │
       ├─ REG servers auto-start
       ├─ SP server auto-starts  
       ├─ SO server auto-starts
       │
       ▼
    (Run SM commands manually)
       │
       ├─ sm1 python3 client.py SM_001 &
       ├─ sm2 python3 client.py SM_002 &
       ├─ ... (10 SMs total)
       │
       ▼
    (Monitor logs)
       │
       ├─ sp tail -f /tmp/sp.log
       ├─ so tail -f /tmp/so.log
       │
       ▼
    (Optional: Trigger attacks)
       │
       ├─ sm1 python3 attacks/replay.py SM_001 &
       ├─ sm2 python3 attacks/dos.py SM_002 &
       │
       ▼
    (Observe IDS alerts)
       │
       ├─ ALERT: Replay detected
       ├─ ALERT: DoS detected
       │
       ▼
    Exit Mininet (Ctrl+D or 'exit')
```

---

## Step-by-Step Detailed Commands

### STEP 1: Start Docker Container
**What:** Enter the Docker container with all PQC dependencies installed

**Command:**
```bash
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim
```

**Expected Output:**
```
root@docker-desktop:/# 
```

**Note:** The `--privileged --net host` flags are required for Mininet to work properly.

---

### STEP 2: Start Mininet Topology
**What:** Initialize the network topology with REG1, REG2, SP, SO, and 10 SMs

**Command:**
```bash
cd /simulation
python3 runTopo.py
```

**Expected Output:**
```
*** Loading custom topology: myTopo
*** Building network
*** Adding controller
*** Starting network...
*** Configuring hosts
*** Starting controller
*** Starting 15 switches
[...]
*** All servers started. Use CLI to interact.
*** Starting CLI:
mininet>
```

**What just happened:**
- Mininet created 15 virtual hosts (10 SMs + 2 REGs + SP + SO)
- REG1 and REG2 automatically started listening on TCP:9998
- SP automatically started listening on TCP:10999 (auth) and UDP:9999 (usage)
- SO automatically started listening on UDP:9999 (for alerts)

---

### STEP 3a: Start Normal Smart Meters (without attacks)
**What:** Launch 10 SMs that will regularly send usage to REG/SP

**Commands in Mininet CLI:**

**Batch 1: REG1 domain (SM1-SM5)**
```bash
mininet> sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
mininet> sm2 python3 client.py SM_002 > /tmp/sm2.log 2>&1 &
mininet> sm3 python3 client.py SM_003 > /tmp/sm3.log 2>&1 &
mininet> sm4 python3 client.py SM_004 > /tmp/sm4.log 2>&1 &
mininet> sm5 python3 client.py SM_005 > /tmp/sm5.log 2>&1 &
```

**Batch 2: REG2 domain (SM6-SM10)**
```bash
mininet> sm6 python3 client.py SM_006 > /tmp/sm6.log 2>&1 &
mininet> sm7 python3 client.py SM_007 > /tmp/sm7.log 2>&1 &
mininet> sm8 python3 client.py SM_008 > /tmp/sm8.log 2>&1 &
mininet> sm9 python3 client.py SM_009 > /tmp/sm9.log 2>&1 &
mininet> sm10 python3 client.py SM_010 > /tmp/sm10.log 2>&1 &
```

**Expected Output (per SM, in logs):**
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

### STEP 3b: Monitor What's Happening (in parallel terminal or split screen)

**Monitor SP (see if auth received and IDS decisions):**
```bash
mininet> sp tail -f /tmp/sp.log | grep "Auth\|ALERT\|Stable"
```

**Expected output:**
```
[SP] ✓ Auth received for SM SM_001 from REG reg1
[SP] ✓ Usage received from SM_001: 2.3 kWh
[SP] ✓ Usage received from SM_001: 1.8 kWh
[SP] STATUS: SM_001 usage=2.0 avg, status=Stable
```

**Monitor SO (see alerts forwarded to System Operator):**
```bash
mininet> so tail -f /tmp/so.log
```

**Expected output:**
```
[*] SYSTEM OPERATOR STARTED
[*] Listening from SP on 0.0.0.0:9999
[*] Forwarding to Host Dashboard...
────────────────────────────────────────────────────────
Received STATUS from SM_001: Stable
Received STATUS from SM_002: Stable
```

**Monitor REG (see signature verification):**
```bash
mininet> reg1 tail -f /tmp/reg1.log | grep "signature\|Forwarded"
```

**Expected output:**
```
[REG reg1] ✅ SM signature verified
[REG reg1] ML-KEM encapsulation completed
[REG reg1] ✓ Forwarded auth for SM_001 to SP via TCP
```

---

### STEP 4: (Optional) Trigger Attacks to Test IDS

**Scenario A: Replay Attack on SM1**

```bash
mininet> sm1 python3 attacks/replay.py SM_001 &
```

**What happens:**
- SM1 sends identical usage value repeatedly (e.g., 2.5 kWh, 2.5 kWh, 2.5 kWh...)
- IDS detects pattern → triggers replay detection
- SP sends ALERT instead of STATUS

**Check result:**
```bash
mininet> sp grep ALERT /tmp/sp.log
```

**Expected output:**
```
[SP] ALERT: SM SM_001 INTRUSION (Replay detected)
```

---

**Scenario B: DoS Attack on SM2**

```bash
mininet> sm2 python3 attacks/dos.py SM_002 &
```

**What happens:**
- SM2 floods SP with usage messages (very high packet rate)
- IDS detects abnormal packet count/jitter
- SP sends ALERT

**Check result:**
```bash
mininet> sp grep "DoS\|ALERT" /tmp/sp.log | tail -5
```

---

**Scenario C: Burst Attack on SM3**

```bash
mininet> sm3 python3 attacks/burst.py SM_003 &
```

**What happens:**
- SM3 suddenly sends very high usage (e.g., 50 kWh instead of 2-3 kWh)
- IDS detects anomaly
- SP sends ALERT

---

### STEP 5: Collect Results & Metrics

**Count total messages received:**
```bash
mininet> sp wc -l /tmp/sp.log
```

**Count alerts vs normal:**
```bash
mininet> sp grep -c "STATUS" /tmp/sp.log
mininet> sp grep -c "ALERT" /tmp/sp.log
```

**Measure PQC auth overhead (from SM log):**
```bash
mininet> sm1 head -5 /tmp/sm1.log
```

**View authentication latency (time from SM start to REG forward):**
```bash
mininet> reg1 grep "Forwarded" /tmp/reg1.log | head -3
```

---

### STEP 6: Exit Mininet

**Option A: Clean exit**
```bash
mininet> exit
```

**Option B: Kill all processes**
```bash
mininet> sh killall python3
mininet> exit
```

---

## Complete Timeline Example (60 seconds)

```
Time 0s:   mininet> (waiting for commands)

Time 1s:   mininet> sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
           [1] 1234

Time 2s:   SM1 enrolls → signature verified by REG1

Time 3s:   mininet> sp tail -f /tmp/sp.log
           [SP] ✓ Auth received for SM SM_001 from REG reg1

Time 4s:   SM1 sends first usage (2.3 kWh)
           [SP] ✓ Usage received from SM_001: 2.3 kWh

Time 7s:   SM1 sends 2nd usage (1.8 kWh)
           [SP] STATUS: SM_001 Stable

Time 10s:  mininet> sm1 python3 attacks/replay.py SM_001 &
           (SM1 now under replay attack)

Time 13s:  SM1 sends repeated usage (2.5, 2.5, 2.5...)
           [SP] ALERT: SM SM_001 INTRUSION (Replay detected)

Time 15s:  mininet> so tail -f /tmp/so.log
           Received ALERT from SM_001: Unstable (Replay)

Time 60s:  mininet> exit
           *** Stopping 15 hosts
           *** Stopping 15 switches
           root@docker-desktop:/#
```

---

## File Structure After Run

```
/tmp/
├── sp.log           ← 500+ lines of SP activity
├── reg1.log         ← 100+ lines of REG1 activity
├── reg2.log         ← 100+ lines of REG2 activity
├── so.log           ← 200+ lines of SO activity
├── sm1.log - sm10.log  ← 50+ lines each (usage messages)
└── mininet.log      ← Network topology logs

/simulation/crypto/
└── global_store.json  ← Enrollment data for SM_001-SM_010
    {
      "devices": {
        "SM_001": {
          "challenge": "...",
          "helper_data": "...",
          "puf_secret": "...",
          "puf_response": "..."
        },
        ...
      }
    }
```

---

## Key Points to Verify Everything Works

✅ **SM Enrollment**: Check for `[ENROLL] Device SM_XXX enrolled` in logs

✅ **SM Authentication**: Check for `[AUTH] Device SM_XXX auth success: True`

✅ **PQC Signature Verification**: Check for `[REG] ✅ SM signature verified`

✅ **KEM Encapsulation**: Check for `[REG] ML-KEM encapsulation completed`

✅ **Auth Forwarding**: Check for `[REG] ✓ Forwarded auth for SM_XXX to SP`

✅ **SP Auth Reception**: Check for `[SP] ✓ Auth received for SM SM_XXX`

✅ **Usage Messages**: Check for `[SP] ✓ Usage received from SM_XXX: X.X kWh`

✅ **IDS Decisions**: Check for `[SP] STATUS: SM_XXX ... Stable` or `ALERT: ... Unstable`

✅ **SO Alerts**: Check for `Received STATUS/ALERT from SM_XXX` in SO logs

---

## If Something Goes Wrong

| Problem | Fix |
|---------|-----|
| "Connection refused" | Make sure REG/SP servers started (check `ps aux`) |
| SM can't find 'crypto' module | Verify `sys.path.insert()` in client.py, reg_server.py |
| No messages in logs | Check `/tmp/` directory exists; logs write there |
| Mininet hangs | Press Ctrl+C, then `pkill -f python3` |
| "No route to host" | Check network config in myTopo.py; ensure default routes |
| Attack not detected | Verify IDS model loaded (`check_hybrid_intrusion_live`) |

---

## Summary: Commands to Copy-Paste

```bash
# Terminal 1
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim
cd /simulation
python3 runTopo.py

# Terminal 2 (in Mininet CLI after topology starts)
sp tail -f /tmp/sp.log
```

**After Mininet is ready, paste these 10 commands (also in Mininet CLI):**
```bash
sm1 python3 client.py SM_001 > /tmp/sm1.log 2>&1 &
sm2 python3 client.py SM_002 > /tmp/sm2.log 2>&1 &
sm3 python3 client.py SM_003 > /tmp/sm3.log 2>&1 &
sm4 python3 client.py SM_004 > /tmp/sm4.log 2>&1 &
sm5 python3 client.py SM_005 > /tmp/sm5.log 2>&1 &
sm6 python3 client.py SM_006 > /tmp/sm6.log 2>&1 &
sm7 python3 client.py SM_007 > /tmp/sm7.log 2>&1 &
sm8 python3 client.py SM_008 > /tmp/sm8.log 2>&1 &
sm9 python3 client.py SM_009 > /tmp/sm9.log 2>&1 &
sm10 python3 client.py SM_010 > /tmp/sm10.log 2>&1 &
```

**Then monitor:**
```bash
sp tail -f /tmp/sp.log | grep "Auth\|Usage\|ALERT"
so tail -f /tmp/so.log
```

**That's it!** The entire PQC-enabled smart grid IDS is running.

