import oqs

# The correct function names are in lowercase and include '_mechanisms'
print("Available KEMs:", oqs.get_enabled_kem_mechanisms())
print("Available Sigs:", oqs.get_enabled_sig_mechanisms())