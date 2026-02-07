# Command Reference Card

## One-Liner Start

```bash
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim && \
cd /simulation && \
python3 runTopo.py
```

---

## Copy-Paste Commands for Mininet CLI

### Start All 10 SMs at Once
```bash
for i in {1..10}; do sm$i python3 client.py SM_$(printf '%03d' $i) > /tmp/sm$i.log 2>&1 &; done
```

### Monitor Everything
```bash
sp tail -f /tmp/sp.log & so tail -f /tmp/so.log & wait
```

### Count Statistics
```bash
sp wc -l /tmp/sp.log
sp grep -c "Auth received" /tmp/sp.log
sp grep -c "ALERT" /tmp/sp.log
so grep -c "STATUS" /tmp/so.log
```

### Test Connectivity
```bash
sm1 ping -c 1 10.0.1.254
sm1 nc -zv 10.0.1.254 9998
sm1 nc -zu 10.0.3.1 9999
```

### Kill All SMs
```bash
sh pkill -f client.py
```

### View Combined Logs
```bash
sh cat /tmp/sp.log /tmp/so.log | grep "ALERT\|STATUS" | sort
```

---

## Attack Scenarios

| Attack | Command | Expected Result |
|--------|---------|-----------------|
| **Replay** | `sm1 python3 attacks/replay.py SM_001 &` | ALERT: Replay detected |
| **DoS** | `sm2 python3 attacks/dos.py SM_002 &` | ALERT: DoS detected |
| **Burst** | `sm3 python3 attacks/burst.py SM_003 &` | ALERT: Usage spike |

---

## Common Mininet Commands

| Task | Command |
|------|---------|
| **List all hosts** | `net` |
| **Show topology links** | `links` |
| **Ping from SM1 to REG1** | `sm1 ping 10.0.1.254` |
| **Check SM1 IP** | `sm1 ifconfig` |
| **Check routes** | `sm1 route` |
| **Kill process on SM1** | `sm1 pkill -f client.py` |
| **Check iperf bandwidth** | `iperf sm1 sp` |
| **Dump traffic** | `sm1 tcpdump -i eth0` |
| **Exit CLI** | `exit` or `Ctrl+D` |

---

## Log File Locations & Sizes

```
/tmp/sp.log         # 500-2000 lines (30-100 KB)
/tmp/reg1.log       # 100-500 lines (5-25 KB)
/tmp/reg2.log       # 100-500 lines (5-25 KB)
/tmp/so.log         # 100-500 lines (5-25 KB)
/tmp/sm{1-10}.log   # 20-50 lines each (1-2 KB each)
```

---

## Performance Targets

| Metric | Expected | How to Measure |
|--------|----------|-----------------|
| **Auth Latency** | <500ms SM→REG→SP | `grep "Forwarded" /tmp/reg1.log` |
| **Usage Throughput** | 3 msgs/sec per SM | `grep -c "Usage received" /tmp/sp.log` |
| **IDS Decision Time** | <100ms | Timestamp delta in logs |
| **False Positive Rate** | <5% on clean data | Count ALERT vs STATUS |
| **Detection Rate** | >95% on attacks | Count ALERT when attack active |

---

## Troubleshooting One-Liners

```bash
# Check if servers running
ps aux | grep -E "client|server|reg|so"

# Check listening ports
netstat -tlnp | grep 9998-9999

# Test TCP connection
echo "test" | nc -w 1 10.0.1.254 9998

# View network interfaces
ifconfig

# Check Mininet logs
cat /tmp/mininet.log | tail -50

# Find errors in SP log
grep ERROR /tmp/sp.log

# Count message types in SP
grep -oE "Auth|Usage|STATUS|ALERT" /tmp/sp.log | sort | uniq -c
```

---

## Performance Profiling

```bash
# Time SM authentication
time python3 -c "
from crypto.sm import SmartMeter
sm = SmartMeter('SM_TEST')
sm.enroll()
sm.authenticate()
"

# Measure auth payload size
python3 -c "
from crypto.sm import SmartMeter
import json
sm = SmartMeter('SM_TEST')
sm.enroll()
sm.authenticate()
auth = sm.build_auth_payload(b'AUTH_REQUEST')
print('Payload size:', len(json.dumps(auth)), 'bytes')
"

# Profile IDS
time python3 -c "
from ids_model import check_hybrid_intrusion_live
# Create dummy feature dict
features = {'sbytes': 100, 'spkts': 5, ...}
result = check_hybrid_intrusion_live(features)
"
```

---

## Data Collection for Report

```bash
# Collect all statistics
(
  echo "=== NETWORK STATS ==="
  echo "Total usage messages:" $(grep -c "Usage received" /tmp/sp.log)
  echo "Total auth messages:" $(grep -c "Auth received" /tmp/sp.log)
  echo "Total alerts:" $(grep -c "ALERT" /tmp/sp.log)
  echo ""
  echo "=== PER-DEVICE STATS ==="
  for i in {1..10}; do
    echo "SM_$i: $(grep -c 'usage=' /tmp/sp.log | head -$i | tail -1) messages"
  done
  echo ""
  echo "=== AUTH TIMING ==="
  grep -E "Forwarded|Auth received" /tmp/sp.log | head -3
  echo ""
  echo "=== ATTACK DETECTION ==="
  grep ALERT /tmp/sp.log | head -5
) | tee /tmp/report.txt
```

---

## Cleanup After Run

```bash
# Kill all processes
pkill -f "python3"
pkill -f "mininet"

# Archive logs
tar czf /tmp/logs_backup.tar.gz /tmp/*.log

# Clear logs for next run
rm -f /tmp/*.log

# Check disk usage
du -sh /tmp/
```

---

## File Editing (if you need to modify)

```bash
# Edit client.py
nano /simulation/client.py

# Edit reg_server.py
nano /simulation/reg_server.py

# Edit server.py (SP)
nano /simulation/server.py

# View Mininet topology
nano /simulation/myTopo.py

# Rebuild Docker image after edits
docker build -t ids-pqc-sim .
```

---

## Git Workflow (if version controlling)

```bash
# Check status
git status

# Commit changes
git add simulation/client.py simulation/reg_server.py
git commit -m "Integrated PQC authentication into SM and REG"

# Push to repo
git push origin <branch>

# View logs
git log --oneline | head -10
```

---

## SSH/Remote Access (if running on remote server)

```bash
# Copy files to remote
scp -r /simulation user@remote:/home/user/

# SSH into remote
ssh user@remote

# Run Docker
ssh user@remote "cd /home/user && docker run --entrypoint bash -it --privileged --net host ids-pqc-sim"

# Get logs from remote
scp user@remote:/tmp/sp.log ./sp_remote.log
```

---

## Docker Best Practices

```bash
# Build with no cache (force rebuild)
docker build --no-cache -t ids-pqc-sim .

# Run with volume mount
docker run -v /simulation:/simulation --entrypoint bash -it --privileged --net host ids-pqc-sim

# Check image size
docker images ids-pqc-sim

# Clean up unused images
docker system prune -a

# Save image to file
docker save ids-pqc-sim > ids-pqc-sim.tar

# Load image from file
docker load < ids-pqc-sim.tar
```

---

