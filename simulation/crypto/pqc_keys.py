import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hashlib
import oqs

def derive_seed(K_puf: bytes) -> bytes:
    return hashlib.sha256(K_puf).digest()

def generate_kyber_keys(seed: bytes):
    """
    Kyber KEM key generation
    NOTE: oqs.KeyEncapsulation.generate_keypair() RETURNS public key
    """
    with oqs.KeyEncapsulation("Kyber768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        return pk, sk

def generate_dilithium_keys(seed: bytes):
    """
    Dilithium signature key generation
    """
    with oqs.Signature("ML-DSA-65") as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return pk, sk