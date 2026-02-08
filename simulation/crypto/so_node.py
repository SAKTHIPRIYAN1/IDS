import oqs
import json
import time
import socket

class SONode:
    def __init__(self, so_id, sp_ip, sp_port):
        self.so_id = so_id
        self.sp_ip = sp_ip
        self.sp_port = sp_port

        self._kyber_pk = None
        self._kyber_sk = None
        self._dilithium_pk = None
        self._dilithium_sk = None

        self.generate_keys()

    def generate_keys(self):
        print("[SO] Generating PQ keys")

        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            self._kyber_pk = kem.generate_keypair()
            self._kyber_sk = kem.export_secret_key()

        with oqs.Signature("ML-DSA-65") as signer:
            self._dilithium_pk = signer.generate_keypair()
            self._dilithium_sk = signer.export_secret_key()

        print("[SO] Dilithium PK length:", len(self._dilithium_pk))

    def build_auth_payload(self):
        with oqs.Signature("ML-DSA-65", self._dilithium_sk) as signer:
            sig = signer.sign(b"AUTH_REQUEST")

        return {
            "so_id": self.so_id,
            "kyber_pk": self._kyber_pk.hex(),
            "dilithium_pk": self._dilithium_pk.hex(),
            "signature": sig.hex(),
            "timestamp": int(time.time())
        }

    def authenticate_with_sp(self):
        payload = self.build_auth_payload()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.sp_ip, self.sp_port))
        sock.sendall(json.dumps(payload).encode())
        resp = json.loads(sock.recv(4096).decode())
        sock.close()

        print("[SO → SP]", resp)
        return resp.get("status") == "AUTH_SUCCESS"
