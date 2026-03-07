import oqs
import json
import time
import socket
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

class SONode:
    def __init__(self, so_id, sp_ip, sp_port):
        self.so_id = so_id
        self.sp_ip = sp_ip
        self.sp_port = sp_port

        self._kyber_pk = None
        self._kyber_sk = None
        self._dilithium_pk = None
        self._dilithium_sk = None

        logging.debug(f"[SO][INIT] SONode initialized with so_id: {self.so_id}, sp_ip: {self.sp_ip}, sp_port: {self.sp_port}")
        self.generate_keys()

    def generate_keys(self):
        logging.debug("[SO][KEY_GENERATION] Starting PQ key generation")

        # Generate Kyber keys
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            self._kyber_pk = kem.generate_keypair()
            self._kyber_sk = kem.export_secret_key()
            logging.debug(f"[SO][KEY_GENERATION] Generated Kyber public key (_kyber_pk): {self._kyber_pk.hex()}")
            logging.debug(f"[SO][KEY_GENERATION] Generated Kyber secret key (_kyber_sk): {self._kyber_sk.hex()}")

        # Generate Dilithium keys
        with oqs.Signature("ML-DSA-65") as signer:
            self._dilithium_pk = signer.generate_keypair()
            self._dilithium_sk = signer.export_secret_key()
            logging.debug(f"[SO][KEY_GENERATION] Generated Dilithium public key (_dilithium_pk): {self._dilithium_pk.hex()}")
            logging.debug(f"[SO][KEY_GENERATION] Generated Dilithium secret key (_dilithium_sk): {self._dilithium_sk.hex()}")

        logging.debug("[SO][KEY_GENERATION] PQ key generation completed")

    def build_auth_payload(self):
        logging.debug("[SO][BUILD_PAYLOAD] Starting to build authentication payload")

        # Step 1: Sign the authentication request
        logging.debug("[SO][BUILD_PAYLOAD] Signing AUTH_REQUEST with Dilithium secret key (_dilithium_sk)")
        with oqs.Signature("ML-DSA-65", self._dilithium_sk) as signer:
            signature = signer.sign(b"AUTH_REQUEST")
        logging.debug(f"[SO][BUILD_PAYLOAD] Generated signature: {signature.hex()}")

        # Step 2: Build the payload
        payload = {
            "so_id": self.so_id,
            "kyber_pk": self._kyber_pk.hex(),
            "dilithium_pk": self._dilithium_pk.hex(),
            "signature": signature.hex(),
            "timestamp": int(time.time())
        }
        logging.debug(f"[SO][BUILD_PAYLOAD] Built authentication payload: {json.dumps(payload, indent=4)}")

        return payload

    def authenticate_with_sp(self):
        logging.debug("[SO][AUTHENTICATE] Starting authentication with SP")

        # Step 1: Build the authentication payload
        payload = self.build_auth_payload()
        logging.debug("[SO][AUTHENTICATE] Authentication payload built successfully")

        # Step 2: Send the payload to SP
        logging.debug(f"[SO][AUTHENTICATE] Connecting to SP at {self.sp_ip}:{self.sp_port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.sp_ip, self.sp_port))
        logging.debug("[SO][AUTHENTICATE] Sending authentication payload to SP")
        sock.sendall(json.dumps(payload).encode())

        # Step 3: Receive and process the response
        logging.debug("[SO][AUTHENTICATE] Waiting for response from SP")
        response = json.loads(sock.recv(4096).decode())
        sock.close()
        logging.debug(f"[SO][AUTHENTICATE] Received response from SP: {json.dumps(response, indent=4)}")

        # Step 4: Check authentication status
        status = response.get("status") == "AUTH_SUCCESS"
        if status:
            logging.debug("[SO][AUTHENTICATE] Authentication with SP succeeded")
        else:
            logging.debug("[SO][AUTHENTICATE] Authentication with SP failed")

        return status
