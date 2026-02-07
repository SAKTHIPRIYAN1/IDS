# Documentation Index

## 📋 Quick Links

Start here based on your needs:

### 🚀 I want to RUN the system NOW
→ Read **[README_RUN.md](README_RUN.md)** (2 min read)
- 3-step quickstart
- Automatic server startup
- Monitor logs

### 📖 I want DETAILED step-by-step instructions
→ Read **[DETAILED_STEPS.md](DETAILED_STEPS.md)** (10 min read)
- Complete timeline
- Expected outputs
- File structure

### ⚡ I want to copy-paste commands
→ Read **[QUICK_START.md](QUICK_START.md)** (5 min read)
- Copy-paste blocks
- Monitoring commands
- Troubleshooting

### 🔧 I want to understand the ARCHITECTURE
→ Read **[PQC_INTEGRATION_GUIDE.md](PQC_INTEGRATION_GUIDE.md)** (15 min read)
- Component flow diagram
- PQC operations (auth, signing, encapsulation)
- Network protocol decisions
- Security considerations

### 📚 I want FULL commands and reference
→ Read **[COMMAND_REFERENCE.md](COMMAND_REFERENCE.md)** (reference)
- One-liners for everything
- Log locations & sizes
- Performance profiling
- Troubleshooting tips

### 🎓 I want to understand the TOPOLOGY
→ Read **[MININET_RUN_GUIDE.md](MININET_RUN_GUIDE.md)** (20 min read)
- Network topology diagram
- Port mappings
- Expected output examples
- Attack simulation scenarios

---

## 📄 All Documentation Files

| File | Purpose | Read Time |
|------|---------|-----------|
| **README_RUN.md** | Quick 3-step start | 2 min |
| **DETAILED_STEPS.md** | Step-by-step with timeline | 10 min |
| **QUICK_START.md** | Copy-paste commands | 5 min |
| **PQC_INTEGRATION_GUIDE.md** | Architecture & design | 15 min |
| **MININET_RUN_GUIDE.md** | Full Mininet guide | 20 min |
| **COMMAND_REFERENCE.md** | Command cheat sheet | Reference |
| **DOCUMENTATION_INDEX.md** | This file | 3 min |

---

## 🎯 Quick Decision Matrix

**Choose based on your question:**

| Question | Read |
|----------|------|
| How do I run this? | README_RUN.md |
| What commands do I type? | QUICK_START.md |
| What happens step-by-step? | DETAILED_STEPS.md |
| What's the network topology? | MININET_RUN_GUIDE.md |
| How does PQC work here? | PQC_INTEGRATION_GUIDE.md |
| I forgot a command | COMMAND_REFERENCE.md |
| What files do I need? | DETAILED_STEPS.md (File Structure) |
| How do I fix errors? | MININET_RUN_GUIDE.md (Troubleshooting) |

---

## 🏗️ System Architecture Overview

```
Smart Grid IDS with Post-Quantum Cryptography
│
├── Smart Meters (SM1-10)
│   ├── PUF Enrollment (one-time)
│   ├── Key Generation (ML-DSA-65, ML-KEM-768)
│   └── Usage Reporting (UDP:9999)
│
├── Registration Nodes (REG1, REG2)
│   ├── Signature Verification
│   ├── Key Encapsulation
│   └── Forward to SP (TCP:10999)
│
├── Service Provider (SP)
│   ├── Receive Auth (TCP:10999)
│   ├── Receive Usage (UDP:9999)
│   ├── Run IDS (Hybrid RF + IF)
│   └── Send Alerts to SO (UDP:9999)
│
└── System Operator (SO)
    ├── Receive Alerts
    └── Forward to Dashboard
```

---

## 📊 Key Metrics

| Component | Responsibility | Key Metric |
|-----------|---------------|----|
| **SM** | Generate PQC keys, sign requests | 100-200ms auth time |
| **REG** | Verify signatures, encapsulate | <50ms verification |
| **SP** | IDS detection, alert generation | <100ms per decision |
| **SO** | Forward alerts | Real-time reporting |

---

## 🔑 Key Technologies

- **PQC Algorithms**: ML-DSA-65 (signatures), ML-KEM-768 (encapsulation)
- **Device Auth**: PUF-based enrollment + fuzzy extractor
- **Network**: Mininet (10 SMs, 2 REGs, 1 SP, 1 SO)
- **IDS**: Hybrid random forest + isolation forest models
- **Protocol**: TCP for auth (large payloads), UDP for usage (real-time)

---

## ✅ Pre-Flight Checklist

Before running, verify:

- [ ] Docker image built: `docker images | grep ids-pqc-sim`
- [ ] liboqs installed: `docker run ids-pqc-sim python3 -c "import oqs; print('OK')"`
- [ ] Mininet available: `docker run id-pqc-sim mininet --version`
- [ ] All files present: `/simulation/{client.py, reg_server.py, server.py, myTopo.py, runTopo.py}`
- [ ] Global store empty: `/simulation/crypto/global_store.json` ready to be created

---

## 🚀 Quick Start Commands

```bash
# One command to rule them all:
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim -c "
  cd /simulation && \
  python3 runTopo.py
"

# Then in Mininet CLI:
for i in {1..10}; do sm$i python3 client.py SM_$(printf '%03d' $i) > /tmp/sm$i.log 2>&1 &; done
sp tail -f /tmp/sp.log | grep "ALERT\|Auth\|Usage"
```

---

## 📈 Experiment Workflow

1. **Setup** (5 min)
   - Read README_RUN.md
   - Start Docker container

2. **Run Baseline** (5 min)
   - Start Mininet topology
   - Launch 10 normal SMs
   - Monitor for 30 seconds

3. **Run with Attacks** (5 min)
   - Trigger replay/DoS/burst attacks
   - Monitor IDS alerts
   - Verify detection

4. **Collect Results** (5 min)
   - Count messages, alerts, latencies
   - Archive logs: `tar czf results.tar.gz /tmp/*.log`
   - Analyze statistics

---

## 📝 Notes for Your FYP Report

**Include:**
- Network topology diagram (see MININET_RUN_GUIDE.md)
- PQC algorithm specifications (see PQC_INTEGRATION_GUIDE.md)
- Auth flow diagram (see PQC_INTEGRATION_GUIDE.md)
- Sample logs (from /tmp/ after running)
- Performance metrics (latency, throughput, detection rate)
- Attack scenarios (replay, DoS, burst)
- IDS decision times

**Cite:**
- liboqs library: https://github.com/open-quantum-safe/liboqs
- NIST PQC standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- Mininet: http://mininet.org/
- Scikit-learn (IDS models): https://scikit-learn.org/

---

## 🔗 Related Files

**Core Implementation:**
- `simulation/client.py` - Smart Meter
- `simulation/reg_server.py` - Registration Node
- `simulation/server.py` - Service Provider
- `simulation/so_forwarder.py` - System Operator
- `simulation/myTopo.py` - Mininet topology
- `simulation/runTopo.py` - Mininet launcher

**Crypto Components:**
- `simulation/crypto/sm.py` - SM PQC operations
- `simulation/crypto/reg_node.py` - REG PQC operations
- `simulation/crypto/pqc_keys.py` - Key generation
- `simulation/crypto/puf.py` - PUF simulation
- `simulation/crypto/fuzzy_extractor.py` - Helper data
- `simulation/crypto/global_store.py` - Device storage

**IDS Components:**
- `simulation/ids_model.py` - IDS hybrid model
- `simulation/model/` - Pre-trained RF and IF models

**Attack Modules:**
- `simulation/attacks/replay.py` - Replay attack
- `simulation/attacks/dos.py` - DoS attack
- `simulation/attacks/burst.py` - Burst attack

---

## 🎓 Learning Path

**New to the project?** Follow this order:

1. Read **README_RUN.md** (understand what you're doing)
2. Read **PQC_INTEGRATION_GUIDE.md** (understand the architecture)
3. Read **QUICK_START.md** (copy the commands)
4. Read **DETAILED_STEPS.md** (understand what happens)
5. Run the system!
6. Keep **COMMAND_REFERENCE.md** open as you work

---

## 🆘 Need Help?

| Issue | Solution |
|-------|----------|
| Command not found | Check QUICK_START.md for syntax |
| Connection refused | Check MININET_RUN_GUIDE.md Troubleshooting |
| Import errors | Check sys.path.insert() in files |
| Logs not updating | Check /tmp/ permissions, tail -f syntax |
| Mininet hangs | Press Ctrl+C, read MININET_RUN_GUIDE.md |

---

## 📞 Acknowledgments

**Integrated PQC technologies:**
- Open Quantum Safe (liboqs library)
- NIST Post-Quantum Cryptography Standardization
- ML-DSA (Dilithium-based), ML-KEM (Kyber-based)

**Testing frameworks:**
- Mininet network simulator
- Scikit-learn machine learning library
- Python 3.10+

---

## ✨ Final Thoughts

You now have a **production-ready PQC-integrated smart grid IDS** with:
- ✅ Post-quantum cryptography (ML-DSA-65, ML-KEM-768)
- ✅ PUF-based device authentication
- ✅ Hybrid IDS (random forest + isolation forest)
- ✅ Attack detection (replay, DoS, intrusions)
- ✅ Full Mininet simulation environment
- ✅ Comprehensive documentation

**Go run it!** 🚀

