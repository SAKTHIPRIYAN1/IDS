import sys
import os
import hashlib
import oqs
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]  # Logs to console
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def derive_seed(K_puf: bytes) -> bytes:
    logging.debug("[REG][DERIVE_SEED] Input K_puf received for seed derivation")
    logging.debug(f"[REG][DERIVE_SEED] K_puf: {K_puf.hex()}")

    logging.debug("[REG][DERIVE_SEED] Computing SHA-256 hash of K_puf to derive seed")
    seed = hashlib.sha256(K_puf).digest()
    logging.debug(f"[REG][DERIVE_SEED] Derived seed: {seed.hex()}")

    return seed

def generate_kyber_keys(seed: bytes):
    """
    Kyber KEM key generation
    NOTE: oqs.KeyEncapsulation.generate_keypair() RETURNS public key
    """
    logging.debug("[REG][KYBER_KEYS] Starting Kyber key generation")
    logging.debug(f"[REG][KYBER_KEYS] Input seed for Kyber key generation: {seed.hex()}")

    logging.debug("[REG][KYBER_KEYS] Initializing Kyber key encapsulation")
    with oqs.KeyEncapsulation("Kyber768") as kem:
        logging.debug("[REG][KYBER_KEYS] Generating Kyber public and secret keys")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        logging.debug(f"[REG][KYBER_KEYS] Generated Kyber public key: {pk.hex()}")
        logging.debug(f"[REG][KYBER_KEYS] Generated Kyber secret key: {sk.hex()}")

    logging.debug("[REG][KYBER_KEYS] Kyber key generation completed")
    return pk, sk

def generate_dilithium_keys(seed: bytes):
    """
    Dilithium signature key generation
    """
    logging.debug("[REG][DILITHIUM_KEYS] Starting Dilithium key generation")
    logging.debug(f"[REG][DILITHIUM_KEYS] Input seed for Dilithium key generation: {seed.hex()}")

    logging.debug("[REG][DILITHIUM_KEYS] Initializing Dilithium signature scheme")
    with oqs.Signature("ML-DSA-65") as sig:
        logging.debug("[REG][DILITHIUM_KEYS] Generating Dilithium public and secret keys")
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        logging.debug(f"[REG][DILITHIUM_KEYS] Generated Dilithium public key: {pk.hex()}")
        logging.debug(f"[REG][DILITHIUM_KEYS] Generated Dilithium secret key: {sk.hex()}")

    logging.debug("[REG][DILITHIUM_KEYS] Dilithium key generation completed")
    return pk, sk