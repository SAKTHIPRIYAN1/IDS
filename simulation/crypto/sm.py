import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from puf_identity import enroll_device, authenticate_device
from pqc_keys import derive_seed, generate_kyber_keys, generate_dilithium_keys
import oqs

class SmartMeter:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self._kyber_sk = None
        self._dilithium_sk = None
        self._kyber_pk = None
        self._dilithium_pk = None

    def enroll(self):
        enroll_device(self.device_id)

    def authenticate(self):

        K_puf = authenticate_device(self.device_id)
        seed = derive_seed(K_puf)

        self._kyber_pk, self._kyber_sk = generate_kyber_keys(seed)
        self._dilithium_pk, self._dilithium_sk = generate_dilithium_keys(seed)

        print("[SM] Keys generated & stored in memory")
        
        '''
        return {
            "kyber_pk": kyber_pk,
            "dilithium_pk": dil_pk,
            "kyber_sk": kyber_sk,       # keep in memory only
            "dilithium_sk": dil_sk     # keep in memory only
        }
        '''

    def build_auth_payload(self, message: bytes) -> dict:
        """
        Builds the authentication request sent to REG
        """
        if self._dilithium_sk is None:
            raise Exception("Authenticate first")

        with oqs.Signature("ML-DSA-65", self._dilithium_sk) as signer:
            signature = signer.sign(message)

        return {
            "device_id": self.device_id,
            "kyber_pk": self._kyber_pk,
            "dilithium_pk": self._dilithium_pk,
            "signature": signature
        }