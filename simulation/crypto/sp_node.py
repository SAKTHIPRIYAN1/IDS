# sp_node.py
import oqs
import hashlib
import hmac
import json
import os
import time


AUTH_DB_FILE = "auth_devices.json"


class SPNode:
    def __init__(self, sp_id: str):
        self.sp_id = sp_id

        # Generate SP Kyber keypair (one-time)
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            self.kyber_pk = kem.generate_keypair()
            self.kyber_sk = kem.export_secret_key()

        print("[SP] Kyber keypair generated")

        # Load authenticated devices
        self.auth_log = self.load_auth_log()

    # --------------------------------------------------
    # Load auth log from JSON
    # --------------------------------------------------
    def load_auth_log(self):
        if os.path.exists(AUTH_DB_FILE):
            with open(AUTH_DB_FILE, "r") as f:
                print("[SP] Loaded existing auth database")
                return json.load(f)
        print("[SP] No existing auth database")
        return []

    # --------------------------------------------------
    # Save auth log to JSON
    # --------------------------------------------------
    def save_auth_log(self):
        with open(AUTH_DB_FILE, "w") as f:
            json.dump(self.auth_log, f, indent=4)
        print("[SP] Auth database saved")

    # --------------------------------------------------
    # Step 1: Verify REG authentication (HMAC proof)
    # --------------------------------------------------
    def verify_reg(self, sk_puf_hash: bytes, m2: bytes, sigma_reg: bytes) -> bool:
        print("[SP][DEBUG] Verifying REG HMAC")
        print(f"[SP][DEBUG] m2              = {m2.hex()}")
        print(f"[SP][DEBUG] sk_puf_hash     = {sk_puf_hash.hex()}")
        print(f"[SP][DEBUG] sigma_reg (rx)  = {sigma_reg.hex()}")

        expected = hmac.new(
            sk_puf_hash,
            m2,
            hashlib.sha256
        ).digest()

        print(f"[SP][DEBUG] sigma_reg (exp) = {expected.hex()}")

        result = hmac.compare_digest(expected, sigma_reg)
        print(f"[SP][DEBUG] HMAC match = {result}")

        return result

    # --------------------------------------------------
    # Step 2: Kyber decapsulation (REG → SP)
    # --------------------------------------------------
    def decapsulate_from_reg(self, kyber_ct: bytes) -> bytes:
        print("[SP][DEBUG] Starting Kyber decapsulation")
        with oqs.KeyEncapsulation("ML-KEM-768", self.kyber_sk) as kem:
            shared_secret = kem.decap_secret(kyber_ct)

        print(f"[SP][DEBUG] K_REG = {shared_secret.hex()}")
        return shared_secret

    # --------------------------------------------------
    # Step 3: Derive session key
    # --------------------------------------------------
    def derive_session_key(self, k_reg: bytes, sm_id: str, reg_id: str, timestamp: int) -> bytes:
        material = (
            k_reg +
            sm_id.encode() +
            reg_id.encode() +
            str(timestamp).encode()
        )

        session_key = hashlib.sha3_256(material).digest()
        print(f"[SP][DEBUG] Session key = {session_key.hex()}")
        return session_key

    # --------------------------------------------------
    # Step 4: Handle REG → SP authentication message
    # --------------------------------------------------
    def handle_reg_message(self, reg_payload: dict) -> dict:
        print("\n[SP] Received authentication from REG")
        print("[SP][DEBUG] Full REG payload:")
        print(json.dumps(reg_payload, indent=4))

        sm_id = reg_payload["sm_id"]
        reg_id = reg_payload["reg_id"]
        timestamp = reg_payload["timestamp"]

        m2 = bytes.fromhex(reg_payload["m2"])
        sigma_reg = bytes.fromhex(reg_payload["sigma_reg"])
        kyber_ct = bytes.fromhex(reg_payload["kyber_ct_reg"])
        sk_puf_hash = bytes.fromhex(reg_payload["sk_puf_hash"])

        # ---- Verify REG ----
        if not self.verify_reg(sk_puf_hash, m2, sigma_reg):
            print("[SP][ERROR] REG authentication FAILED")
            raise Exception("[SP] REG authentication FAILED")

        print("[SP] REG authentication SUCCESS")

        # ---- Kyber decapsulation ----
        k_reg = self.decapsulate_from_reg(kyber_ct)

        # ---- Session key derivation ----
        session_key = self.derive_session_key(
            k_reg,
            sm_id,
            reg_id,
            timestamp
        )

        # ---- Log authenticated SM ----
        log_entry = {
            "sm_id": sm_id,
            "reg_id": reg_id,
            "timestamp": timestamp,
            "session_key_hash": hashlib.sha256(session_key).hexdigest(),
            "status": "AUTH_SUCCESS"
        }

        self.auth_log.append(log_entry)
        self.save_auth_log()

        print(f"[SP] SM {sm_id} authenticated via REG {reg_id}\n")

        return log_entry
