import oqs

# Settings
kemalg = "Kyber512" 

print(f"--- 1. Alice generates keys using {kemalg} ---")
with oqs.KeyEncapsulation(kemalg) as client:
    # Alice generates her public and secret key
    public_key = client.generate_keypair()
    print(f"Alice's Public Key: {public_key.hex()[:60]}...") # Printing just the start

    # --- 2. Bob encapsulates a secret ---
    # Bob uses Alice's public key to create a shared secret and a ciphertext
    ciphertext, shared_secret_bob = client.encap_secret(public_key)
    print(f"\n--- 2. Bob sends Ciphertext to Alice ---")
    print(f"Ciphertext: {ciphertext.hex()[:60]}...")
    print(f"Bob's Shared Secret:   {shared_secret_bob.hex()}")

    # --- 3. Alice decapsulates ---
    # Alice uses her secret key and the ciphertext to get the SAME secret
    shared_secret_alice = client.decap_secret(ciphertext)
    print(f"\n--- 3. Alice decapsulates using her Secret Key ---")
    print(f"Alice's Shared Secret: {shared_secret_alice.hex()}")

    # Verification
    if shared_secret_alice == shared_secret_bob:
        print("\n✅ SUCCESS: Shared secrets match! Quantum-safe tunnel established.")
    else:
        print("\n❌ FAILURE: Secrets do not match.")