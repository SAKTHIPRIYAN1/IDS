# Quick Reference: Mininet PQC-IDS Commands

## Start Everything (3 Commands)

```bash
# 1. Enter container
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim

# 2. Start Mininet topology
cd /simulation
python3 runTopo.py

# 3. In Mininet CLI, start SMs (copy-paste these 10 commands):
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

---

## Monitor Logs (in Mininet)

```bash
# Watch SP alerts
sp tail -f /tmp/sp.log | grep "ALERT\|Auth\|Usage"

# Watch SO notifications
so tail -f /tmp/so.log

# Check REG auth
reg1 tail -f /tmp/reg1.log
reg2 tail -f /tmp/reg2.log

# Check specific SM
sm1 tail -f /tmp/sm1.log
```

---

## Trigger Attacks

```bash
# Replay attack on SM1
sm1 python3 attacks/replay.py SM_001 &

# DoS attack on SM2
sm2 python3 attacks/dos.py SM_002 &

# Burst attack on SM3
sm3 python3 attacks/burst.py SM_003 &
```

---

## Verify PQC Working

```bash
# Check auth payload size
sp grep "Auth JSON size" /tmp/sp.log

# Verify signature checks
reg1 grep "signature verified" /tmp/reg1.log

# Monitor encapsulation
reg1 grep "ML-KEM" /tmp/reg1.log
```

---

## Clean Up

```bash
# Inside Mininet:
mininet> exit

# Or:
mininet> sh killall python3
```

---

## Typical Output Sequence

```
Time 0s:   Servers start (REG1, REG2, SP, SO)
Time 1s:   SMs connect to network
Time 2s:   SM1 enrolls (PUF) → stored in global_store.json
Time 3s:   SM1 authenticates → generates keys
Time 4s:   SM1 signs AUTH_REQUEST → sends to REG1:9998 (TCP)
Time 4.1s: REG1 verifies signature → ✅ OK
Time 4.2s: REG1 encapsulates with ML-KEM → creates kyber_ct
Time 4.3s: REG1 forwards auth to SP:10999 (TCP)
Time 4.4s: SP receives auth → stores in authenticated_devices[SM_001]
Time 5s:   SM1 sends usage to SP:9999 (UDP)
Time 5.1s: SP runs IDS on usage → Stable → sends STATUS to SO:9999
Time 5.2s: SO receives STATUS → logs "SM_001: Stable"
Time 6-60s: Repeat usage messages every 3s
```

---

## Key Metrics

- **Auth Latency**: ~100-200ms (SM → REG → SP)
- **Usage Throughput**: ~3 messages/sec per SM = 30 msgs/sec total (10 SMs)
- **IDS Decision**: ~50-100ms (check features → detect anomaly → send alert)
- **Auth Payload Size**: ~12.9 KB (PQC algorithms produce large keys)

---

## Mininet CLI Tips

```bash
# Get host IP
mininet> sm1 ifconfig

# Test connectivity
mininet> sm1 ping 10.0.1.254

# Check routing
mininet> sm1 route

# Kill a process on SM1
mininet> sm1 pkill -f client.py

# Run command in background
mininet> sm1 <cmd> &

# List all hosts
mininet> net

# Show links
mininet> links
```

---

## Troubleshooting One-Liners

```bash
# Check if servers are running
mininet> sh ps aux | grep python3 | grep -E "client|server|reg"

# Test TCP connectivity SM1 → REG1
mininet> sm1 nc -zv 10.0.1.254 9998

# Test UDP connectivity SM1 → SP
mininet> sm1 nc -zu 10.0.3.1 9999

# Check logs for errors
mininet> sp grep ERROR /tmp/sp.log
mininet> reg1 grep ERROR /tmp/reg1.log

# Count received messages
mininet> sp wc -l /tmp/sp.log

# Show last 20 lines of alerts
mininet> sp tail -20 /tmp/sp.log | grep ALERT
```

---

## Expected Files Generated During Run

```
/tmp/
├── sp.log          # Service Provider output
├── reg1.log        # REG1 output
├── reg2.log        # REG2 output
├── so.log          # System Operator output
├── sm1.log - sm10.log  # Smart Meter logs
└── mininet.log     # Mininet topology logs

/simulation/crypto/
└── global_store.json  # PUF enrollment data for all devices
```

---

## One-Command Summary

**Everything from scratch (replace <ID> with your container ID):**

```bash
# Terminal 1: Start Mininet
docker exec -it <ID> bash -c "cd /simulation && python3 runTopo.py"

# Terminal 2: Monitor (after Mininet is ready, in Mininet CLI):
sp tail -f /tmp/sp.log

# Terminal 3: Start SMs (in Mininet CLI):
for i in {1..10}; do eval "sm$i python3 client.py SM_$(printf '%03d' $i) > /tmp/sm$i.log 2>&1 &"; done

# Terminal 4: Monitor alerts (in Mininet CLI):
so tail -f /tmp/so.log | grep "STATUS\|ALERT"
```

---

