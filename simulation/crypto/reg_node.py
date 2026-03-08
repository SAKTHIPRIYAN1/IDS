# reg_node.py
import oqs
import hashlib
import hmac
import secrets
import time
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

class REGNode:
    def __init__(self, reg_id: str):
        self.reg_id = reg_id
        logging.debug(f"[REG][INIT] REGNode initialized with reg_id: {self.reg_id}")

    # --------------------------------------------------
    # Step 1: Verify SM authentication request
    # --------------------------------------------------
    def verify_sm(self, auth_payload: dict, message: bytes) -> bool:
        logging.debug("[REG][VERIFY_SM] Verifying SM authentication request")
        logging.debug(f"[REG][VERIFY_SM] Received auth_payload: {auth_payload}")
        logging.debug(f"[REG][VERIFY_SM] Received message: {message.hex()}")

        dil_pk = bytes.fromhex(auth_payload["dilithium_pk"])
        signature = bytes.fromhex(auth_payload["signature"])
        logging.debug(f"[REG][VERIFY_SM] Dilithium public key: {dil_pk.hex()}")
        logging.debug(f"[REG][VERIFY_SM] Signature: {signature.hex()}")

        with oqs.Signature("ML-DSA-65") as verifier:
            is_valid = verifier.verify(message, signature, dil_pk)

        logging.debug(f"[REG][VERIFY_SM] SM authentication result: {'SUCCESS' if is_valid else 'FAILED'}")
        return is_valid

    # --------------------------------------------------
    # Step 2: Derive REG PUF secret
    # SK_PUF = H(PUF(challenge) || r_REG)
    # --------------------------------------------------
    def derive_sk_puf(self, challenge: bytes):
        logging.debug("[REG][DERIVE_SK_PUF] Deriving SK_PUF")
        logging.debug(f"[REG][DERIVE_SK_PUF] Challenge before hash: {challenge.hex()}")

        # Simulated PUF response
        logging.debug("[REG][DERIVE_SK_PUF] Generating simulated PUF response")
        puf_resp = hashlib.sha256((self.reg_id + challenge.hex()).encode()).digest()
        logging.debug(f"[REG][DERIVE_SK_PUF] Simulated PUF response: {puf_resp.hex()}")

        r_reg = secrets.token_bytes(16)
        logging.debug(f"[REG][DERIVE_SK_PUF] Generated random r_REG: {r_reg.hex()}")

        sk_puf = hashlib.sha256(puf_resp + r_reg).digest()
        logging.debug(f"[REG][DERIVE_SK_PUF] Derived SK_PUF: {sk_puf.hex()}")

        return sk_puf, r_reg

    # --------------------------------------------------
    # Step 3: Sign M2 using SK_PUF (HMAC)
    # --------------------------------------------------
    def sign_m2(self, sk_puf: bytes, m2: bytes):
        logging.debug("[REG][SIGN_M2] Signing M2 using SK_PUF")
        logging.debug(f"[REG][SIGN_M2] SK_PUF: {sk_puf.hex()}")
        logging.debug(f"[REG][SIGN_M2] M2 before signing: {m2.hex()}")

        sk_puf_hash = hashlib.sha256(sk_puf).digest()
        logging.debug(f"[REG][SIGN_M2] Hashed SK_PUF: {sk_puf_hash.hex()}")

        sigma_reg = hmac.new(sk_puf_hash, m2, hashlib.sha256).digest()
        logging.debug(f"[REG][SIGN_M2] Generated HMAC (sigma_reg): {sigma_reg.hex()}")

        return sigma_reg, sk_puf_hash

    # --------------------------------------------------
    # Step 4: Kyber encapsulation for SP
    # C_REG, K_REG = Encap(PK_SP)
    # --------------------------------------------------
    def encapsulate_for_sp(self, sp_kyber_pk_hex: str):
        logging.debug("[REG][ENCAPSULATE_FOR_SP] Performing Kyber encapsulation for SP")
        logging.debug(f"[REG][ENCAPSULATE_FOR_SP] SP Kyber public key: {sp_kyber_pk_hex}")

        sp_pk = bytes.fromhex(sp_kyber_pk_hex)
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ct_reg, k_reg = kem.encap_secret(sp_pk)

        logging.debug(f"[REG][ENCAPSULATE_FOR_SP] Generated ciphertext (C_REG): {ct_reg.hex()}")
        logging.debug(f"[REG][ENCAPSULATE_FOR_SP] Generated shared secret (K_REG): {k_reg.hex()}")

        return ct_reg, k_reg

    # --------------------------------------------------
    # Step 5: Build REG → SP message
    # --------------------------------------------------
    def build_message_to_sp(
        self,
        sm_id: str,
        m2: bytes,
        sigma_reg: bytes,
        ct_reg: bytes,
        sk_puf_hash: bytes,
        reg_id: str,
        reg_ip: str,
        sm_ip: str,
        sm_port: int
    ):
        logging.debug("[REG][BUILD_MESSAGE_TO_SP] Building message to SP")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] SM ID: {sm_id}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] M2: {m2.hex()}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] Sigma_REG: {sigma_reg.hex()}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] Kyber ciphertext (C_REG): {ct_reg.hex()}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] Hashed SK_PUF: {sk_puf_hash.hex()}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] REG ID: {reg_id}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] REG IP: {reg_ip}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] SM IP: {sm_ip}")
        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] SM Port: {sm_port}")

        message = {
            "sm_id": sm_id,
            "reg_id": self.reg_id,
            "timestamp": int(time.time()),
            "m2": m2.hex(),
            "sigma_reg": sigma_reg.hex(),
            "kyber_ct_reg": ct_reg.hex(),
            "sk_puf_hash": sk_puf_hash.hex(),
            "reg_id": reg_id,
            "reg_ip": reg_ip,
            "sm_ip": sm_ip,
            "sm_port": sm_port
            
        }

        logging.debug(f"[REG][BUILD_MESSAGE_TO_SP] Built message: {message}")
        return message
