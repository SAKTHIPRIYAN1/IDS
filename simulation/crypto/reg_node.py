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
        - dilithium_pk (hex string)
        - signature (hex string)
        """

        # Convert hex strings back to bytes
        dil_pk = bytes.fromhex(auth_payload["dilithium_pk"])
        signature = bytes.fromhex(auth_payload["signature"])

        with oqs.Signature("ML-DSA-65") as verifier:
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
    def encapsulate_for_sm(self, sm_kyber_pk_hex: str):
        """
        Perform Kyber encapsulation using SM public key (hex string)
        """
        # Convert hex string back to bytes
        sm_kyber_pk = bytes.fromhex(sm_kyber_pk_hex)

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ciphertext, shared_secret = kem.encap_secret(sm_kyber_pk)

        print("[REG] ML-KEM encapsulation completed")

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
        REG → SP payload (hex-encode bytes for JSON)
        """
        return {
            "sm_id": auth_payload["device_id"],
            "reg_id": self.reg_id,
            "timestamp": int(time.time()),
            "kyber_ct": kyber_ct.hex(),
            "sm_dilithium_pk": auth_payload["dilithium_pk"],
            "sm_kyber_pk": auth_payload["kyber_pk"],
            "signature": auth_payload["signature"]
        }

if __name__ == "__main__":
    from sm import SmartMeter

    # Initialize SM & REG
    sm = SmartMeter("SM_001")
    reg = REGNode("REG_01")

    # Enrollment (one-time)
    sm.enroll()

    # SM authentication
    sm.authenticate()
    message = b"AUTH_REQUEST"
    auth_payload = sm.build_auth_payload(message)

    # REG verifies SM
    if reg.verify_sm(auth_payload, message):
        kyber_ct, ss_reg_sm = reg.encapsulate_for_sm(
            auth_payload["kyber_pk"]
        )

        print("[REG] Shared secret length:", len(ss_reg_sm))

        forward_msg = reg.build_forward_message(
            auth_payload,
            kyber_ct
        )

        print("\n[REG] Forwarding to SP:")
        print(forward_msg.keys())