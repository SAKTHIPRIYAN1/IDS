import oqs
import hashlib
import time


class SPNode:
    def __init__(self, sp_id: str):
        self.sp_id = sp_id

    # -----------------------------
    # Step 1: Verify SM again (optional but recommended)
    # -----------------------------
    def verify_sm_signature(
        self,
        sm_pk: bytes,
        signature: bytes,
        message: bytes
    ) -> bool:
        with oqs.Signature("ML-DSA-65") as verifier:
            return verifier.verify(message, signature, sm_pk)

    # -----------------------------
    # Step 2: Kyber decapsulation
    # -----------------------------
    def decapsulate_from_reg(
        self,
        kyber_ct: bytes,
        sm_kyber_sk: bytes
    ) -> bytes:
        """
        In real system:
        - SM would decaps
        - SP derives session key from forwarded secrets

        For simulation:
        - We allow SP to decaps (simplified)
        """
        with oqs.KeyEncapsulation("Kyber768", sm_kyber_sk) as kem:
            return kem.decap_secret(kyber_ct)

    # -----------------------------
    # Step 3: Session key derivation
    # -----------------------------
    def derive_session_key(
        self,
        shared_secret: bytes,
        sm_id: str,
        reg_id: str,
        timestamp: int
    ) -> bytes:
        material = (
            shared_secret +
            sm_id.encode() +
            reg_id.encode() +
            str(timestamp).encode()
        )
        return hashlib.sha3_256(material).digest()

    # -----------------------------
    # Step 4: Handle REG message
    # -----------------------------
    def handle_reg_message(
        self,
        reg_payload: dict,
        message: bytes,
        sm_kyber_sk: bytes
    ) -> dict:
        print("[SP] Received auth from REG")

        valid = self.verify_sm_signature(
            reg_payload["sm_dilithium_pk"],
            reg_payload["signature"],
            message
        )

        if not valid:
            raise Exception("[SP] SM signature invalid")

        ss = self.decapsulate_from_reg(
            reg_payload["kyber_ct"],
            sm_kyber_sk
        )

        session_key = self.derive_session_key(
            ss,
            reg_payload["sm_id"],
            reg_payload["reg_id"],
            reg_payload["timestamp"]
        )

        print("[SP] Session key derived")

        return {
            "sm_id": reg_payload["sm_id"],
            "reg_id": reg_payload["reg_id"],
            "timestamp": reg_payload["timestamp"],
            "session_key_hash": hashlib.sha256(session_key).hexdigest(),
            "status": "AUTH_SUCCESS"
        }
