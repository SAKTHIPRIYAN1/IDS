# reg_node.py
import oqs
import hashlib
import hmac
import secrets
import time


class REGNode:
    def __init__(self, reg_id: str):
        self.reg_id = reg_id

    # --------------------------------------------------
    # Step 1: Verify SM authentication request
    # --------------------------------------------------
    def verify_sm(self, auth_payload: dict, message: bytes) -> bool:
        dil_pk = bytes.fromhex(auth_payload["dilithium_pk"])
        signature = bytes.fromhex(auth_payload["signature"])

        with oqs.Signature("ML-DSA-65") as verifier:
            is_valid = verifier.verify(
                message,
                signature,
                dil_pk
            )

        if is_valid:
            print("[REG] SM authentication SUCCESS")
        else:
            print("[REG] SM authentication FAILED")

        return is_valid

    # --------------------------------------------------
    # Step 2: Derive REG PUF secret
    # SK_PUF = H(PUF(challenge) || r_REG)
    # --------------------------------------------------
    def derive_sk_puf(self, challenge: bytes):
        # Simulated PUF response (acceptable for thesis)
        puf_resp = hashlib.sha256(
            (self.reg_id + challenge.hex()).encode()
        ).digest()

        r_reg = secrets.token_bytes(16)

        sk_puf = hashlib.sha256(puf_resp + r_reg).digest()

        print("[REG] SK_PUF derived")
        return sk_puf, r_reg

    # --------------------------------------------------
    # Step 3: Sign M2 using SK_PUF (HMAC)
    # --------------------------------------------------
    def sign_m2(self, sk_puf: bytes, m2: bytes):
        sk_puf_hash = hashlib.sha256(sk_puf).digest()

        sigma_reg = hmac.new(
            sk_puf_hash,
            m2,
            hashlib.sha256
        ).digest()

        print("[REG] M2 signed using HASHED SK_PUF")
        return sigma_reg, sk_puf_hash


    # --------------------------------------------------
    # Step 4: Kyber encapsulation for SP
    # C_REG, K_REG = Encap(PK_SP)
    # --------------------------------------------------
    def encapsulate_for_sp(self, sp_kyber_pk_hex: str):
        sp_pk = bytes.fromhex(sp_kyber_pk_hex)

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ct_reg, k_reg = kem.encap_secret(sp_pk)

        print("[REG] Kyber encapsulation for SP complete")
        return ct_reg, k_reg

    # --------------------------------------------------
    # Step 5: Build REG → SP message
    # --------------------------------------------------
        # reg_node.py
    def build_message_to_sp(
    self,
    sm_id: str,
    m2: bytes,
    sigma_reg: bytes,
    ct_reg: bytes,
    sk_puf_hash: bytes,
    reg_id: str,
    reg_ip: str
):
        return {
            "sm_id": sm_id,
            "reg_id": self.reg_id,
            "timestamp": int(time.time()),
            "m2": m2.hex(),
            "sigma_reg": sigma_reg.hex(),
            "kyber_ct_reg": ct_reg.hex(),
            "sk_puf_hash": sk_puf_hash.hex(),
            "reg_id": reg_id,
            "reg_ip": reg_ip
        }
