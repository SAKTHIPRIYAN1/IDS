import socket
from event_emitter import emit
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 9999))

def func(regId:str):
    while True:
        data, addr = s.recvfrom(2048)
        emit(regId,"sp")

if __name__ == "__main__":
    argv = sys.argv
    if len(argv) < 2:
        print("Usage: python reg_forwarder.py <regId>")
        sys.exit(1)
    # getting the regid as cmd argument
    regId = argv[1]
    func(regId)
    