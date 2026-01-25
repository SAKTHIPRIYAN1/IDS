import oqs
import hashlib
import os
import time


class REGNode:
    def __init__(self, reg_id: str):
        self.reg_id = reg_id

    # --------------------------------------------------
    # Step 1: Verify SM authentication request
    # --------------------------------------------------
    def verify_sm(self, auth_payload: dict, message: bytes) -> bool:
        """
        auth_payload contains:
        - device_id
        - dilithium_pk
        - signature
        """

        dil_pk = auth_payload["dilithium_pk"]
        signature = auth_payload["signature"]

        with oqs.Signature("Dilithium3") as verifier:
            is_valid = verifier.verify(
                message,
                signature,
                dil_pk
            )

        if not is_valid:
            print("[REG] ❌ SM signature verification FAILED")
        else:
            print("[REG] ✅ SM signature verified")

        return is_valid

    # --------------------------------------------------
    # Step 2: Kyber encapsulation for SM
    # --------------------------------------------------
    def encapsulate_for_sm(self, sm_kyber_pk: bytes):
        """
        Perform Kyber encapsulation using SM public key
        """

        with oqs.KeyEncapsulation("Kyber768") as kem:
            ciphertext, shared_secret = kem.encap_secret(sm_kyber_pk)

        print("[REG] Kyber encapsulation completed")

        return ciphertext, shared_secret

    # --------------------------------------------------
    # Step 3: Build message for SP (next hop)
    # --------------------------------------------------
    def build_forward_message(
        self,
        auth_payload: dict,
        kyber_ct: bytes
    ):
        """
        REG → SP payload
        """
        return {
            "sm_id": auth_payload["device_id"],
            "reg_id": self.reg_id,
            "timestamp": int(time.time()),
            "kyber_ct": kyber_ct,
            "sm_dilithium_pk": auth_payload["dilithium_pk"],
            "sm_kyber_pk": auth_payload["kyber_pk"],
            "signature": auth_payload["signature"]
        }