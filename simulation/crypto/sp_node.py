# sp_node.py
import oqs
import hashlib
import hmac
import json
import os
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

AUTH_DB_FILE = "auth_devices.json"


class SPNode:
    def __init__(self, sp_id: str):
        self.sp_id = sp_id

        logging.debug(f"[SP][INIT] Initializing SPNode with sp_id: {self.sp_id}")

        # Generate SP Kyber keypair (one-time)
        logging.debug("[SP][KEY_GENERATION] Generating Kyber keypair")
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            self.kyber_pk = kem.generate_keypair()
            self.kyber_sk = kem.export_secret_key()
            logging.debug(f"[SP][KEY_GENERATION] Generated Kyber public key (kyber_pk): {self.kyber_pk.hex()}")
            logging.debug(f"[SP][KEY_GENERATION] Generated Kyber secret key (kyber_sk): {self.kyber_sk.hex()}")

        # Load authenticated devices
        self.auth_log = self.load_auth_log()

    # --------------------------------------------------
    # Load auth log from JSON
    # --------------------------------------------------
    def load_auth_log(self):
        logging.debug("[SP][LOAD_AUTH_LOG] Loading authentication log")
        if os.path.exists(AUTH_DB_FILE):
            with open(AUTH_DB_FILE, "r") as f:
                logging.debug("[SP][LOAD_AUTH_LOG] Loaded existing auth database")
                return json.load(f)
        logging.debug("[SP][LOAD_AUTH_LOG] No existing auth database found")
        return []

    # --------------------------------------------------
    # Save auth log to JSON
    # --------------------------------------------------
    def save_auth_log(self):
        logging.debug("[SP][SAVE_AUTH_LOG] Saving authentication log")
        with open(AUTH_DB_FILE, "w") as f:
            json.dump(self.auth_log, f, indent=4)
        logging.debug("[SP][SAVE_AUTH_LOG] Auth database saved successfully")

    # --------------------------------------------------
    # Verify REG authentication (HMAC proof)
    # --------------------------------------------------
    def verify_reg(self, sk_puf_hash: bytes, m2: bytes, sigma_reg: bytes) -> bool:
        logging.debug("[SP][VERIFY_REG] Verifying REG HMAC")
        logging.debug(f"[SP][VERIFY_REG] Received m2: {m2.hex()}")
        logging.debug(f"[SP][VERIFY_REG] Received sk_puf_hash: {sk_puf_hash.hex()}")
        logging.debug(f"[SP][VERIFY_REG] Received sigma_reg: {sigma_reg.hex()}")

        logging.debug("[SP][VERIFY_REG] Computing expected HMAC")
        expected = hmac.new(sk_puf_hash, m2, hashlib.sha256).digest()
        logging.debug(f"[SP][VERIFY_REG] Computed expected sigma_reg: {expected.hex()}")

        result = hmac.compare_digest(expected, sigma_reg)
        logging.debug(f"[SP][VERIFY_REG] HMAC match result: {result}")

        return result

    # --------------------------------------------------
    # Kyber decapsulation (REG → SP)
    # --------------------------------------------------
    def decapsulate_from_reg(self, kyber_ct: bytes) -> bytes:
        logging.debug("[SP][DECAPSULATE] Starting Kyber decapsulation")
        logging.debug(f"[SP][DECAPSULATE] Received Kyber ciphertext (kyber_ct): {kyber_ct.hex()}")

        with oqs.KeyEncapsulation("ML-KEM-768", self.kyber_sk) as kem:
            shared_secret = kem.decap_secret(kyber_ct)

        logging.debug(f"[SP][DECAPSULATE] Decapsulated shared secret (k_reg): {shared_secret.hex()}")
        return shared_secret

    # --------------------------------------------------
    # Derive session key
    # --------------------------------------------------
    def derive_session_key(self, k_reg: bytes, sm_id: str, reg_id: str, timestamp: int) -> bytes:
        logging.debug("[SP][DERIVE_SESSION_KEY] Deriving session key")
        logging.debug(f"[SP][DERIVE_SESSION_KEY] Received k_reg: {k_reg.hex()}")
        logging.debug(f"[SP][DERIVE_SESSION_KEY] Received sm_id: {sm_id}")
        logging.debug(f"[SP][DERIVE_SESSION_KEY] Received reg_id: {reg_id}")
        logging.debug(f"[SP][DERIVE_SESSION_KEY] Received timestamp: {timestamp}")

        material = (
            k_reg +
            sm_id.encode() +
            reg_id.encode() +
            str(timestamp).encode()
        )

        logging.debug("[SP][DERIVE_SESSION_KEY] Computing session key using SHA3-256")
        session_key = hashlib.sha3_256(material).digest()
        logging.debug(f"[SP][DERIVE_SESSION_KEY] Derived session key: {session_key.hex()}")

        return session_key

    # --------------------------------------------------
    # Handle REG → SP authentication message
    # --------------------------------------------------
    def handle_reg_message(self, reg_payload: dict) -> dict:
        logging.debug("[SP][HANDLE_REG_MESSAGE] Received authentication message from REG")
        logging.debug(f"[SP][HANDLE_REG_MESSAGE] Full REG payload: {json.dumps(reg_payload, indent=4)}")

        sm_id = reg_payload["sm_id"]
        reg_id = reg_payload["reg_id"]
        timestamp = reg_payload["timestamp"]
        reg_ip = reg_payload["reg_ip"]

        m2 = bytes.fromhex(reg_payload["m2"])
        sigma_reg = bytes.fromhex(reg_payload["sigma_reg"])
        kyber_ct = bytes.fromhex(reg_payload["kyber_ct_reg"])
        sk_puf_hash = bytes.fromhex(reg_payload["sk_puf_hash"])

        # ---- Verify REG ----
        logging.debug("[SP][HANDLE_REG_MESSAGE] Verifying REG authentication")
        if not self.verify_reg(sk_puf_hash, m2, sigma_reg):
            logging.error("[SP][HANDLE_REG_MESSAGE] REG authentication FAILED")
            raise Exception("[SP] REG authentication FAILED")
        logging.debug("[SP][HANDLE_REG_MESSAGE] REG authentication SUCCESS")

        # ---- Kyber decapsulation ----
        logging.debug("[SP][HANDLE_REG_MESSAGE] Performing Kyber decapsulation")
        k_reg = self.decapsulate_from_reg(kyber_ct)

        # ---- Session key derivation ----
        logging.debug("[SP][HANDLE_REG_MESSAGE] Deriving session key")
        session_key = self.derive_session_key(k_reg, sm_id, reg_id, timestamp)

        # ---- Log authenticated SM ----
        logging.debug("[SP][HANDLE_REG_MESSAGE] Logging authenticated SM")
        log_entry = {
            "sm_id": sm_id,
            "reg_id": reg_id,
            "reg_ip": reg_ip,
            "timestamp": timestamp,
            "session_key_hash": hashlib.sha256(session_key).hexdigest(),
            "status": "AUTH_SUCCESS"
        }

        self.auth_log.append(log_entry)
        self.save_auth_log()

        logging.debug(f"[SP][HANDLE_REG_MESSAGE] SM {sm_id} authenticated via REG {reg_id}")
        return log_entry
