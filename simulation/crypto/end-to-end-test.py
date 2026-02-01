from sm import SmartMeter
from reg_node import REGNode
from sp_node import SPNode
from so_dashboard import SODashboard

message = b"AUTH_REQUEST"

sm = SmartMeter("SM_001")
reg = REGNode("REG_01")
sp = SPNode("SP_CC")
so = SODashboard()

# One-time
sm.enroll()

# Session
sm.authenticate()
auth_payload = sm.build_auth_payload(message)

# REG
assert reg.verify_sm(auth_payload, message)
ct, _ = reg.encapsulate_for_sm(auth_payload["kyber_pk"])
reg_msg = reg.build_forward_message(auth_payload, ct)

# SP (simulation only: pass sm kyber sk)
event = sp.handle_reg_message(
    reg_msg,
    message,
    sm._kyber_sk      # ⚠️ simulation only
)

# SO dashboard
so.display_event(event)
