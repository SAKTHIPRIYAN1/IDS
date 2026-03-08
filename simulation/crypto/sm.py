import sys
import os
import logging
import socket

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf_identity import enroll_device, authenticate_device
from pqc_keys import derive_seed, generate_kyber_keys, generate_dilithium_keys
import oqs

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

class SmartMeter:

    def __init__(self, device_id: str):
        self.device_id = device_id
        self._kyber_sk = None
        self._dilithium_sk = None
        self._kyber_pk = None
        self._dilithium_pk = None

        logging.debug(f"[SM][INIT] SmartMeter initialized with device_id: {self.device_id}")

    def enroll(self):
        logging.debug(f"[SM][ENROLL] Starting enrollment")
        enroll_device(self.device_id)
        logging.debug(f"[SM][ENROLL] Enrollment completed")

    def authenticate(self):

        logging.debug(f"[SM][AUTH] Starting authentication")

        K_puf = authenticate_device(self.device_id)
        logging.debug(f"[SM][AUTH] Retrieved PUF key")

        seed = derive_seed(K_puf)

        self._kyber_pk, self._kyber_sk = generate_kyber_keys(seed)
        self._dilithium_pk, self._dilithium_sk = generate_dilithium_keys(seed)

        print("[SM] Keys generated & stored in memory")

    def build_auth_payload(self, message: bytes, sm_port: int) -> dict:

        if self._dilithium_sk is None:
            raise Exception("Authenticate first")

        with oqs.Signature("ML-DSA-65", self._dilithium_sk) as signer:
            signature = signer.sign(message)
        print(self.device_id)
        sm_ip = "10.0.1." + self.device_id[2:] if int(self.device_id[2:]) <= 5 else "10.0.2." + str(int(self.device_id[2:])-5)
        print(f"\n\n\n\n[SM] SM IP determined as {sm_ip} based on device_id\n\n\n")
        payload = {
            "device_id": self.device_id,
            "kyber_pk": self._kyber_pk.hex(),
            "dilithium_pk": self._dilithium_pk.hex(),
            "signature": signature.hex(),
            "sm_ip": sm_ip,
            "sm_port": sm_port
        }

        logging.debug(f"[SM][PAYLOAD] Built payload: {payload}")

        return payload