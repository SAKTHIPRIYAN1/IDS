import hashlib
import os
import random
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

class SimulatedPUF:
    def __init__(self, device_secret: bytes):
        logging.debug("[REG][PUF_INIT] Initializing SimulatedPUF")
        logging.debug(f"[REG][PUF_INIT] Device secret provided: {device_secret.hex()}")
        self.device_secret = device_secret
        logging.debug("[REG][PUF_INIT] SimulatedPUF initialized successfully")

    def challenge(self, challenge: bytes, noise_rate=0.05) -> bytes:
        logging.debug("[REG][PUF_CHALLENGE] Received challenge for PUF response generation")
        logging.debug(f"[REG][PUF_CHALLENGE] Challenge before hash: {challenge.hex()}")
        logging.debug(f"[REG][PUF_CHALLENGE] Noise rate: {noise_rate}")

        # Step 1: Compute ideal response
        logging.debug("[REG][PUF_CHALLENGE] Computing hash of device_secret concatenated with challenge")
        ideal_response = hashlib.sha256(self.device_secret + challenge).digest()
        logging.debug(f"[REG][PUF_CHALLENGE] Ideal response (hash of device_secret + challenge): {ideal_response.hex()}")

        # Step 2: Add noise to the response
        logging.debug("[REG][PUF_CHALLENGE] Adding noise to the ideal response")
        noisy_response = bytearray(ideal_response)
        for i in range(len(noisy_response)):
            if random.random() < noise_rate:
                noisy_response[i] ^= 1 << random.randint(0, 7)
        logging.debug(f"[REG][PUF_CHALLENGE] Noisy response after adding noise: {bytes(noisy_response).hex()}")

        return bytes(noisy_response)

def generate_device_secret():
    logging.debug("[REG][PUF_GENERATE_SECRET] Generating random device secret")
    device_secret = os.urandom(32)
    logging.debug(f"[REG][PUF_GENERATE_SECRET] Generated device secret: {device_secret.hex()}")
    return device_secret