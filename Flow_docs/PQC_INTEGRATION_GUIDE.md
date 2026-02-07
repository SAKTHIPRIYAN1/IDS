# PQC Integration Guide: SM → REG → SP → SO

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                   PQC-Enabled Smart Grid                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Smart Meter (SM)              Registration Node (REG)          │
│  ┌─────────────────┐            ┌──────────────────┐            │
│  │ client.py       │            │ reg_server.py    │            │
│  │ ─────────────── │            │ ──────────────── │            │
│  │ 1. Enroll       │  TCP/9998  │ 1. Verify sig    │            │
│  │    (PUF-based)  │──────────→ │ 2. ML-KEM encap  │            │
│  │ 2. Authenticate │ (auth)     │ 3. Forward auth  │            │
│  │    (key gen)    │            │    to SP         │            │
│  │ 3. Sign payload │            │                  │            │
│  │ 4. Send usage   │  UDP/9999  └──────────────────┘            │
│  │    (unencrypted)│─┐                    │                     │
│  └─────────────────┘ │                    │ TCP/10999           │
│                      │                    │ (auth)              │
│                      │                    ▼                     │
│                      │          Service Provider (SP)           │
│                      │          ┌──────────────────┐            │
│                      │          │ server.py        │            │
│                      │          │ ──────────────── │            │
│                      └─────────→│ 1. Receive auth  │            │
│                                 │    from REG (TCP)│            │
│                                 │ 2. Receive usage │            │
│                                 │    from SM (UDP) │            │
│                                 │ 3. IDS check     │            │
│                                 │ 4. XAI explain   │            │
│                                 │ 5. Forward to SO │            │
│                                 └──────────────────┘            │
│                                        │ UDP/9999               │
│                                        ▼                        │
│                          System Operator (SO)                   │
│                          ┌──────────────────┐                   │
│                          │ so_forwarder.py  │                   │
│                          │ ──────────────── │                   │
│                          │ 1. Receive alert │                   │
│                          │ 2. Forward to    │                   │
│                          │    dashboard     │                   │
│                          └──────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Smart Meter (SM) - `client.py`

**PQC Operations:**
- **Enrollment (once)**: Device generates PUF challenge/response, fuzzy extractor derives key
- **Authentication (per session)**:
  - Generate Kyber768 (KEM) keypair
  - Generate ML-DSA-65 (signature) keypair
  - Sign `"AUTH_REQUEST"` message

**Flow:**
# Auth payload contains (hex-encoded):
{
  "device_id": "SM_001",
  "kyber_pk": "2368 bytes (hex = 4736 chars)",
  "dilithium_pk": "3904 bytes (hex = 7808 chars)",  
  "signature": "6618 bytes (hex = 13236 chars)"      # Total ~12KB JSON
}

# Send via TCP to REG:9998 (large payload)


**Launch:**
```bash
docker run --entrypoint bash -it --privileged --net host ids-pqc-sim
cd /simulation
python3 client.py SM_001
```

---

### 2. Registration Node (REG) - `reg_server.py`

**PQC Operations:**
- **Verify Signature**: Check SM's ML-DSA-65 signature using public key from auth payload
- **Key Encapsulation**: Use SM's Kyber768 public key to encapsulate shared secret

**Flow:**
```python
# REG listens on TCP:9998
auth_payload = json.loads(data)  # Receive from SM

# Verify signature
reg.verify_sm(auth_payload, b"AUTH_REQUEST")  # ✓ or ✗

# If valid: encapsulate
kyber_ct, shared_secret = reg.encapsulate_for_sm(auth_payload["kyber_pk"])

# Forward to SP via TCP:10999 (auth)
forward_msg = {
  "sm_id": "SM_001",
  "reg_id": "REG_01",
  "kyber_ct": "..." (hex),
  "sm_dilithium_pk": "...",
  "sm_kyber_pk": "...",
  "signature": "...",
  "timestamp": ...
}
```

**Launch:**
```bash
python3 reg_server.py REG_01
```

---

### 3. Service Provider (SP) - `server.py`

**PQC Operations:**
- **Auth Reception**: Accept large auth messages from REG via TCP
- **Device Tracking**: Store authentication state per device
- **IDS Decision**: Check flow anomalies, replay attacks, intrusions

**Flow:**
```python
# SP listens on TWO ports:
# - TCP:10999 (auth from REG) → handle_auth_from_reg()
# - UDP:9999  (usage from SM)  → main loop

# Upon auth from REG:
authenticated_devices[sm_id] = {
  "timestamp": time.time(),
  "kyber_ct": "...",
  "signature": "...",
  "reg_id": "REG_01"
}

# Upon usage from SM:
if sm_id in authenticated_devices:
    # IDS check
    is_intrusion = check_hybrid_intrusion_live(features)
    
    # Forward to SO
    report = {
      "type": "ALERT|STATUS",
      "smId": sm_id,
      "usage": 2.5,
      "status": "Stable|Unstable",
      "reason": "DoS|Replay|Normal"
    }
```

**Launch:**
```bash
python3 server.py
```

---

### 4. System Operator (SO) - `so_forwarder.py`

**Operations:**
- **Alert Reception**: Receive IDS decisions from SP (UDP:9999)
- **Dashboard Forward**: Send alerts to Host Dashboard (external)

**Launch:**
```bash
python3 so_forwarder.py
```

---

## Testing the Integration

### Test 1: Local Integration Test (Fastest)
```bash
cd /simulation/crypto/test
python3 test_pqc_servers.py
```
Expected output:
```
[SP] Listening on TCP 127.0.0.1:10999 (auth) and UDP 127.0.0.1:9999 (usage)
[REG] Listening on TCP 127.0.0.1:9998
[ENROLL] Device SM_002 enrolled
[AUTH] Device SM_002 auth success: True
[SM] Auth sent to REG via TCP
[REG] ✅ SM signature verified
[REG] ML-KEM encapsulation completed
[REG] ✓ Forwarded auth for SM_002 to SP via TCP
[SP] ✓ Auth received for SM SM_002 from REG REG_01
[SP] ✓ Usage received from SM_002: 1.5 kWh
[SP] ✓ Usage received from SM_002: 1.6 kWh
[SP] ✓ Usage received from SM_002: 1.7 kWh
```

### Test 2: Multi-Device with Mininet (Production)
```bash
cd /simulation
python3 runTopo.py
# Then in Mininet:
# SM: python3 client.py SM_001
# REG: python3 reg_server.py REG_01
# SP: python3 server.py
# SO: python3 so_forwarder.py
```

---

## Key Design Decisions

| Aspect | Decision | Reason |
|--------|----------|--------|
| **Auth Protocol** | TCP (not UDP) | Auth payload ~12KB, exceeds UDP MTU (~1500B) |
| **Usage Protocol** | UDP | Small, frequent, non-critical, low-latency |
| **Signature Algo** | ML-DSA-65 | NIST-standardized, medium security/speed |
| **KEM Algo** | ML-KEM-768 | NIST-standardized, comparable to Kyber768 |
| **PUF Enrollment** | One-time | Device secret stored in `/crypto/global_store.json` |
| **Key Derivation** | SHA256(PUF_response) | Deterministic, reproducible |

---

## Security Considerations

✓ **PQC-Resistant**: All cryptography uses post-quantum algorithms  
✓ **Device Authentication**: SM must sign every auth request  
✓ **Replay Protection**: IDS detects repeated patterns  
✓ **Integrity**: Signatures prevent tampering  
✗ **Encryption**: Usage messages are plaintext (add TLS if needed)  

---

## Extending the Integration

### Add Usage Encryption (Optional)
```python
# In client.py, after authentication:
kyber_ct, shared_secret = kem.encap_secret(sp_kyber_pk)

# Encrypt each usage message with shared_secret
usage_encrypted = AES_GCM_encrypt(usage_json, shared_secret)
sock.sendto(usage_encrypted, (SP_IP, SP_PORT))
```

### Add Multiple REGs
```bash
python3 reg_server.py REG_01  # Listens on 9998
python3 reg_server.py REG_02  # Listens on 9999 (change LISTEN_PORT)
```

### Monitor PQC Overhead
```bash
# In test output, measure:
# - Key generation time
# - Signature size (13KB hex)
# - Encapsulation time
# - Network latency (TCP vs UDP)
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: crypto` | Ensure `sys.path.insert(0, ...)` in all files |
| `liboqs version mismatch` warning | Not a blocker, but upgrade `liboqs-python==0.15.0` in `requirements.txt` |
| `Connection refused` on TCP:10999 | Ensure SP server is running on correct port |
| `JSON decode error` on REG | Check if auth payload is complete; TCP should not truncate |
| Device enrollment fails | Check `/simulation/crypto/global_store.json` permissions |

---

## Next Steps

1. **Deploy to Mininet**: Run full topology with multiple SMs, REGs, SP, SO
2. **Add Intrusion Patterns**: Test IDS with DoS/Replay attacks
3. **Measure Performance**: Benchmark crypto operations, latency, throughput
4. **Encrypt Usage**: Add AES-GCM encryption with shared secrets from KEM
5. **Audit Logs**: Store auth/IDS events in database for forensics

