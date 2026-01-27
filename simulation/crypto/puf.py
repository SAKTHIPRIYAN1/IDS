import hashlib
import os
import random

class SimulatedPUF:
    def __init__(self, device_secret: bytes):
        self.device_secret = device_secret

    def challenge(self, challenge: bytes, noise_rate=0.05) -> bytes:
        # Ideal response
        base = hashlib.sha256(self.device_secret + challenge).digest()

        # Add noise (bit flips)
        noisy = bytearray(base)
        for i in range(len(noisy)):
            if random.random() < noise_rate:
                noisy[i] ^= 1 << random.randint(0, 7)

        return bytes(noisy)

def generate_device_secret():
    return os.urandom(32)