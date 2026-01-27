import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf import SimulatedPUF, generate_device_secret
from fuzzy_extractor import helper_gen, helper_rep
from global_store import register_device, get_device

def enroll_device(device_id: str):
    device_secret = generate_device_secret()
    puf = SimulatedPUF(device_secret)

    challenge = os.urandom(32)
    response = puf.challenge(challenge, noise_rate=0.0)

    key, helper_data = helper_gen(response)

    register_device(device_id, {
        "challenge": challenge.hex(),
        "helper_data": helper_data.hex(),
        "puf_secret": device_secret.hex(),  # for simulation only
        "puf_response": response.hex()
    })

    print(f"[ENROLL] Device {device_id} enrolled")

def authenticate_device(device_id: str):
    device = get_device(device_id)
    if not device:
        raise Exception("Device not found")

    challenge = bytes.fromhex(device["challenge"])
    helper_data = bytes.fromhex(device["helper_data"])
    device_secret = bytes.fromhex(device["puf_secret"])

    puf = SimulatedPUF(device_secret)
    noisy_response = puf.challenge(challenge)

    reconstructed_key = helper_rep(noisy_response, helper_data)

    def hamming_distance(a: bytes, b: bytes) -> int:
        return sum(bin(x ^ y).count("1") for x, y in zip(a, b))

    stored_response = bytes.fromhex(device["puf_response"])
    distance = hamming_distance(noisy_response, stored_response)

    success = distance < 10

    print(f"[AUTH] Device {device_id} auth success: {success}")
    # print(reconstructed_key)
    return reconstructed_key if success else None