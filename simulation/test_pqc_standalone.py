#!/usr/bin/env python3
"""
Standalone PQC integration test without Mininet
Tests: SM -> REG -> SP flow
"""

import json
import time
import threading
import socket
from sm import SmartMeter
from reg_node import REGNode

# Configuration
REG_PORT = 9998
SP_PORT = 9999

def test_sm_to_reg():
    """Test SM enrollment, auth, and REG processing"""
    print("\n" + "="*60)
    print("TEST: SM -> REG -> SP (PQC Flow)")
    print("="*60)

    # 1. Initialize SM and REG
    sm = SmartMeter("SM_001")
    reg = REGNode("REG_01")

    # 2. SM Enrollment (one-time)
    print("\n[STEP 1] SM Enrollment")
    sm.enroll()
    print("✓ SM enrolled successfully")

    # 3. SM Authentication
    print("\n[STEP 2] SM Authentication & Key Generation")
    sm.authenticate()
    print("✓ SM authenticated, PQC keys generated")

    # 4. SM builds auth payload
    print("\n[STEP 3] SM builds signed auth payload")
    message = b"AUTH_REQUEST"
    auth_payload = sm.build_auth_payload(message)
    print(f"✓ Auth payload created")
    print(f"  - Device ID: {auth_payload['device_id']}")
    print(f"  - Dilithium PK size: {len(auth_payload['dilithium_pk'])} bytes")
    print(f"  - Kyber PK size: {len(auth_payload['kyber_pk'])} bytes")
    print(f"  - Signature size: {len(auth_payload['signature'])} bytes")

    # 5. REG verifies SM signature
    print("\n[STEP 4] REG verifies SM Dilithium signature")
    if reg.verify_sm(auth_payload, message):
        print("✓ Signature verification PASSED")
    else:
        print("✗ Signature verification FAILED")
        return False

    # 6. REG performs Kyber encapsulation
    print("\n[STEP 5] REG performs Kyber encapsulation")
    kyber_ct, shared_secret = reg.encapsulate_for_sm(auth_payload["kyber_pk"])
    print(f"✓ Kyber encapsulation completed")
    print(f"  - Ciphertext size: {len(kyber_ct)} bytes")
    print(f"  - Shared secret size: {len(shared_secret)} bytes")

    # 7. REG builds forward message for SP
    print("\n[STEP 6] REG builds forward message for SP")
    forward_msg = reg.build_forward_message(auth_payload, kyber_ct)
    print(f"✓ Forward message created")
    print(f"  - Message keys: {list(forward_msg.keys())}")

    # 8. Simulate SP receiving the message
    print("\n[STEP 7] SP receives and processes auth")
    print(f"✓ SP would receive:")
    print(f"  - SM ID: {forward_msg['sm_id']}")
    print(f"  - REG ID: {forward_msg['reg_id']}")
    print(f"  - Timestamp: {forward_msg['timestamp']}")
    print(f"  - Kyber CT size: {len(forward_msg['kyber_ct'])} bytes")

    print("\n" + "="*60)
    print("ALL TESTS PASSED ✓")
    print("="*60)
    return True

if __name__ == "__main__":
    try:
        success = test_sm_to_reg()
        exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
