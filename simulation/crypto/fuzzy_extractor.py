import hashlib
import os

def helper_gen(puf_response: bytes):
    """
    Enrollment phase
    """
    key = hashlib.sha256(puf_response).digest()
    helper_data = bytes(a ^ b for a, b in zip(puf_response, key))
    return key, helper_data

def helper_rep(puf_response: bytes, helper_data: bytes):
    """
    Reconstruction phase
    """
    recovered_key = bytes(a ^ b for a, b in zip(puf_response, helper_data))
    final_key = hashlib.sha256(recovered_key).digest()
    return final_key