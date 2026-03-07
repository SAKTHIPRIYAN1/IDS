import sys
import os
import logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf_identity import enroll_device, authenticate_device
from pqc_keys import derive_seed, generate_kyber_keys, generate_dilithium_keys
import oqs

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
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
        logging.debug(f"[SM][ENROLL] Starting enrollment for device_id: {self.device_id}")
        enroll_device(self.device_id)
        logging.debug(f"[SM][ENROLL] Enrollment completed for device_id: {self.device_id}")

    def authenticate(self):
        logging.debug(f"[SM][AUTH] Starting authentication for device_id: {self.device_id}")

        # Step 1: Authenticate device and retrieve PUF key
        K_puf = authenticate_device(self.device_id)
        logging.debug(f"[SM][AUTH] Retrieved PUF key (K_puf): {K_puf.hex()}")

        # Step 2: Derive seed from PUF key
        logging.debug(f"[SM][AUTH] Deriving seed from PUF key (K_puf)")
        seed = derive_seed(K_puf)
        logging.debug(f"[SM][AUTH] Derived seed: {seed.hex()}")

        # Step 3: Generate Kyber keys
        logging.debug(f"[SM][AUTH] Generating Kyber keys using derived seed")
        self._kyber_pk, self._kyber_sk = generate_kyber_keys(seed)
        logging.debug(f"[SM][AUTH] Generated Kyber public key (kyber_pk): {self._kyber_pk.hex()}")
        logging.debug(f"[SM][AUTH] Generated Kyber secret key (kyber_sk): {self._kyber_sk.hex()}")

        # Step 4: Generate Dilithium keys
        logging.debug(f"[SM][AUTH] Generating Dilithium keys using derived seed")
        self._dilithium_pk, self._dilithium_sk = generate_dilithium_keys(seed)
        logging.debug(f"[SM][AUTH] Generated Dilithium public key (dilithium_pk): {self._dilithium_pk.hex()}")
        logging.debug(f"[SM][AUTH] Generated Dilithium secret key (dilithium_sk): {self._dilithium_sk.hex()}")

        logging.debug(f"[SM][AUTH] Authentication completed for device_id: {self.device_id}")
        print("[SM] Keys generated & stored in memory")

    def build_auth_payload(self, message: bytes) -> dict:
        """
        Builds the authentication request sent to REG
        """
        logging.debug(f"[SM][BUILD_PAYLOAD] Starting to build authentication payload for device_id: {self.device_id}")
        logging.debug(f"[SM][BUILD_PAYLOAD] Input message to be signed: {message.hex()}")

        if self._dilithium_sk is None:
            logging.error(f"[SM][BUILD_PAYLOAD] Dilithium secret key not found. Authenticate first.")
            raise Exception("Authenticate first")

        # Step 1: Sign the message using Dilithium secret key
        logging.debug(f"[SM][BUILD_PAYLOAD] Signing message with Dilithium secret key")
        with oqs.Signature("ML-DSA-65", self._dilithium_sk) as signer:
            signature = signer.sign(message)
        logging.debug(f"[SM][BUILD_PAYLOAD] Generated signature: {signature.hex()}")

        # Step 2: Build the payload
        payload = {
            "device_id": self.device_id,
            "kyber_pk": self._kyber_pk.hex(),
            "dilithium_pk": self._dilithium_pk.hex(),
            "signature": signature.hex()
        }
        logging.debug(f"[SM][BUILD_PAYLOAD] Built authentication payload: {payload}")

        return payload