# FINAL SUMMARY: How to Run Everything

## TL;DR (3 Steps)

```bash
# Step 1: Start container
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim

# Step 2: Start Mininet (in container)
cd /simulation && python3 runTopo.py

# Step 3: In Mininet CLI, start SMs (copy all 10):
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

Done! You're running PQC-integrated smart grid IDS with Mininet.

---

## What Happens Automatically

When you run `python3 runTopo.py`, the following start automatically:
- ✅ **REG1** (listening on TCP:9998) - Authentication verification
- ✅ **REG2** (listening on TCP:9998) - Authentication verification  
- ✅ **SP** (listening on TCP:10999 & UDP:9999) - IDS & alert generation
- ✅ **SO** (listening on UDP:9999) - Alert reception & forwarding

You only need to manually start the **10 Smart Meters**.

---

## What You'll See

### In SP Log:
```
[SP] ✓ Auth received for SM SM_001 from REG reg1
[SP] ✓ Usage received from SM_001: 2.3 kWh
[SP] STATUS: SM_001 Stable
```

### In SO Log:
```
Received STATUS from SM_001: Stable
Received STATUS from SM_002: Stable
```

### In REG1 Log:
```
[REG reg1] ✅ SM signature verified
[REG reg1] ML-KEM encapsulation completed
[REG reg1] ✓ Forwarded auth for SM_001 to SP
```

---

## Monitor in Real-Time (in Mininet CLI)

```bash
# Watch alerts
sp tail -f /tmp/sp.log | grep "ALERT\|Auth\|Usage"

# Watch SO
so tail -f /tmp/so.log

# Watch specific SM
sm1 tail -f /tmp/sm1.log
```

---

## Trigger Attacks (Optional, in Mininet CLI)

```bash
# Replay attack
sm1 python3 attacks/replay.py SM_001 &

# DoS attack
sm2 python3 attacks/dos.py SM_002 &

# Burst attack
sm3 python3 attacks/burst.py SM_003 &
```

Then check: `sp grep ALERT /tmp/sp.log`

---

## Exit

```bash
mininet> exit
```

---

## What Gets Logged

```
/tmp/
├── sp.log (IDS & alerts)
├── reg1.log, reg2.log (auth verification)
├── so.log (received alerts)
└── sm1.log - sm10.log (SM activity)
```

---

## Files to Read for Details

- **PQC_INTEGRATION_GUIDE.md** - Full architecture, components, security
- **MININET_RUN_GUIDE.md** - Detailed commands, troubleshooting, metrics
- **QUICK_START.md** - Cheat sheet of common commands
- **DETAILED_STEPS.md** - Step-by-step with timeline and expected output

---

## That's Everything!

Your PQC-enabled Smart Grid IDS is ready to run. The integration includes:

✅ **PQC Auth**: ML-DSA-65 signatures, ML-KEM-768 encapsulation  
✅ **PUF-based Device Enrollment**: Stored in global_store.json  
✅ **IDS**: Hybrid random forest model detecting DoS/Replay/Intrusions  
✅ **Automated Forwarding**: SM → REG → SP → SO  
✅ **Mininet Topology**: 10 SMs, 2 REGs, 1 SP, 1 SO  
✅ **Attack Simulation**: Replay, DoS, Burst attack modules  

Good luck with your FYP!
