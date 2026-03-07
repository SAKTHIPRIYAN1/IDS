import sys
import os
import logging
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf import SimulatedPUF, generate_device_secret
from fuzzy_extractor import helper_gen, helper_rep
from global_store import register_device, get_device

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

def enroll_device(device_id: str):
    logging.debug(f"[REG][ENROLL] Starting enrollment for device: {device_id}")
    
    # Step 1: Generate device secret
    logging.debug("[REG][ENROLL] Generating device secret")
    device_secret = generate_device_secret()
    logging.debug(f"[REG][ENROLL] Generated device_secret: {device_secret.hex()}")
    
    # Step 2: Initialize PUF
    logging.debug("[REG][ENROLL] Initializing SimulatedPUF with device_secret")
    puf = SimulatedPUF(device_secret)
    logging.debug("[REG][ENROLL] SimulatedPUF initialized successfully")

    # Step 3: Generate challenge and response
    logging.debug("[REG][ENROLL] Generating random challenge")
    challenge = os.urandom(32)
    logging.debug(f"[REG][ENROLL] Generated challenge: {challenge.hex()}")

    logging.debug("[REG][ENROLL] Generating PUF response (noise-free)")
    response = puf.challenge(challenge, noise_rate=0.0)
    logging.debug(f"[REG][ENROLL] Generated PUF response (noise-free): {response.hex()}")

    # Step 4: Generate key and helper data
    logging.debug("[REG][ENROLL] Generating key and helper data using fuzzy extractor")
    key, helper_data = helper_gen(response)
    logging.debug(f"[REG][ENROLL] Generated key: {key.hex()}")
    logging.debug(f"[REG][ENROLL] Generated helper_data: {helper_data.hex()}")

    # Step 5: Register device
    logging.debug("[REG][ENROLL] Registering device with challenge, helper_data, and PUF secret")
    register_device(device_id, {
        "challenge": challenge.hex(),
        "helper_data": helper_data.hex(),
        "puf_secret": device_secret.hex(),  # for simulation only
        "puf_response": response.hex()
    })
    logging.debug(f"[REG][ENROLL] Device {device_id} registered successfully")
    print(f"[ENROLL] Device {device_id} enrolled")

def authenticate_device(device_id: str):
    logging.debug(f"[REG][AUTH] Starting authentication for device: {device_id}")
    
    # Step 1: Retrieve device data
    logging.debug("[REG][AUTH] Retrieving device data from global store")
    device = get_device(device_id)
    if not device:
        logging.error(f"[REG][AUTH] Device {device_id} not found in global store")
        raise Exception("Device not found")
    logging.debug("[REG][AUTH] Retrieved device data successfully")

    # Step 2: Extract stored data
    logging.debug("[REG][AUTH] Extracting stored challenge, helper_data, and PUF secret")
    challenge = bytes.fromhex(device["challenge"])
    helper_data = bytes.fromhex(device["helper_data"])
    device_secret = bytes.fromhex(device["puf_secret"])
    logging.debug(f"[REG][AUTH] Extracted challenge: {challenge.hex()}")
    logging.debug(f"[REG][AUTH] Extracted helper_data: {helper_data.hex()}")
    logging.debug(f"[REG][AUTH] Extracted device_secret: {device_secret.hex()}")

    # Step 3: Initialize PUF and generate noisy response
    logging.debug("[REG][AUTH] Initializing SimulatedPUF with extracted device_secret")
    puf = SimulatedPUF(device_secret)
    logging.debug("[REG][AUTH] Generating noisy PUF response using extracted challenge")
    noisy_response = puf.challenge(challenge)
    logging.debug(f"[REG][AUTH] Generated noisy PUF response: {noisy_response.hex()}")

    # Step 4: Reconstruct key
    logging.debug("[REG][AUTH] Reconstructing key using fuzzy extractor and noisy response")
    reconstructed_key = helper_rep(noisy_response, helper_data)
    logging.debug(f"[REG][AUTH] Reconstructed key: {reconstructed_key.hex()}")

    # Step 5: Calculate Hamming distance
    logging.debug("[REG][AUTH] Calculating Hamming distance between noisy response and stored response")
    def hamming_distance(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    stored_response = bytes.fromhex(device["puf_response"])
    distance = hamming_distance(noisy_response, stored_response)
    logging.debug(f"[REG][AUTH] Calculated Hamming distance: {distance}")

    # Step 6: Determine authentication success
    logging.debug("[REG][AUTH] Determining authentication success based on Hamming distance")
    success = distance < 10
    logging.debug(f"[REG][AUTH] Authentication success: {success}")
    print(f"[AUTH] Device {device_id} auth success: {success}")
    
    return reconstructed_key if success else None