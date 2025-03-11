################################################################################
# ECDSA (Elliptic Curve Digital Signature Algorithm) Implementation
################################################################################
# This script demonstrates a manual implementation of ECDSA, a cryptographic
# algorithm used for digital signatures using ECC (Elliptic Curve Cryptography).
# 
# ECDSA is widely used in cryptocurrencies, secure communications, and
# certificate authorities to verify data integrity and authenticity.
#
# Overview:
# - Uses NIST P-256 curve parameters
# - Implements core ECC operations (point addition, doubling, scalar multiplication)
# - Demonstrates complete ECDSA workflow (key generation, signing, verification)
#
# ECDSA Security Components:
# - Private key: A randomly generated integer d (kept secret by the signer)
# - Public key: A point Q = d × G on the curve (published)
# - Nonce: A random value k generated for each signature (critical for security)
# - Hash function: SHA-256 to create message digest
#
# ECDSA Workflow:
# 1. Signing:
#    - Generate a random nonce k
#    - Calculate point R = k × G and extract r = R_x mod n
#    - Calculate s = k^(-1) × (hash(m) + d × r) mod n
#    - Signature is the pair (r,s)
#
# 2. Verification:
#    - Calculate u1 = hash(m) × s^(-1) mod n
#    - Calculate u2 = r × s^(-1) mod n
#    - Calculate point P = u1×G + u2×Q
#    - Signature is valid if P_x mod n equals r
#
# Security depends on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
# Given points P and Q=kP, it's computationally infeasible to determine k.
################################################################################
import os
import hashlib
import secrets

################################################################################
# Step 1: Define the elliptic curve parameters (NIST P-256 curve)
################################################################################
# y² = x³ - 3x + b (mod p) 

# The prime modulus
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
# Parameter b in the curve equation
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
# Order of the base point (number of points on the curve)
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
# Base point G coordinates
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

print("Elliptic Curve Parameters:")
print(f"Curve: y² = x³ - 3x + b (mod p)")
print(f"p = {p}")
print(f"b = {b}")
print(f"n = {n}")
print(f"Base point G = ({hex(Gx)}, {hex(Gy)})")
print()

################################################################################
# Step 2: Implement ECC Point Operations
################################################################################

def point_addition(P, Q, p):
    """Add two points on the elliptic curve y² = x³ - 3x + b (mod p)"""
    if P is None:  # P at infinity
        return Q
    if Q is None:  # Q at infinity
        return P
    
    x1, y1 = P
    x2, y2 = Q
    
    # If P == Q, use point doubling formula
    if x1 == x2 and y1 == y2:
        return point_doubling(P, p)
    
    # If P == -Q, return point at infinity
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    # Calculate slope
    m = ((y2 - y1) * pow(x2 - x1, p-2, p)) % p
    
    # Calculate new point coordinates
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p
    
    return (x3, y3)

def point_doubling(P, p):
    """Double a point on the elliptic curve y² = x³ - 3x + b (mod p)"""
    if P is None:  # Point at infinity
        return None
    
    x, y = P
    
    # If y == 0, doubling gives point at infinity
    if y == 0:
        return None
    
    # Calculate slope (tangent at point P)
    m = ((3 * x * x - 3) * pow(2 * y, p-2, p)) % p
    
    # Calculate new point coordinates
    x3 = (m*m - 2*x) % p
    y3 = (m*(x - x3) - y) % p
    
    return (x3, y3)

def scalar_multiplication(k, P, p):
    """Multiply point P by scalar k using double-and-add algorithm"""
    if k == 0 or P is None:
        return None
    
    if k < 0:
        # Negative scalar means multiply by |k| and negate the result
        k = -k
        P = (P[0], -P[1] % p)
    
    result = None
    addend = P
    
    # Double-and-add algorithm
    while k:
        if k & 1:  # if lowest bit of k is 1
            result = point_addition(result, addend, p)
        addend = point_doubling(addend, p)
        k >>= 1  # Right shift k by 1 bit
    
    return result

print("ECC Operations Test:")
G = (Gx, Gy)
G2 = point_doubling(G, p)
print(f"G + G = 2G = ({hex(G2[0])}, {hex(G2[1])})")
G3 = point_addition(G2, G, p)
print(f"2G + G = 3G = ({hex(G3[0])}, {hex(G3[1])})")
G4 = scalar_multiplication(4, G, p)
print(f"4G = ({hex(G4[0])}, {hex(G4[1])})")
print()

################################################################################
# Step 3: Generate ECC Key Pair
################################################################################

# Generate a private key (random integer less than n)
private_key = secrets.randbelow(n)
# Compute public key Q = private_key * G
public_key = scalar_multiplication(private_key, G, p)

print("Key Generation:")
print(f"Private key: {hex(private_key)}")
print(f"Public key: ({hex(public_key[0])}, {hex(public_key[1])})")
print()

################################################################################
# Step 4: ECDSA Signature Generation
################################################################################

def hash_message(message):
    """Create a SHA-256 hash of the message and convert to integer"""
    h = hashlib.sha256(message).digest()
    return int.from_bytes(h, byteorder='big')
    
def generate_signature(message, private_key):
    """
    Generate ECDSA signature for a message using the private key
    
    ECDSA signature generation:
    1. Hash the message to create a digest
    2. Select a secure random nonce k (different for each signature!)
    3. Calculate the curve point R = k*G and extract r = R_x mod n
    4. Calculate s = k^(-1) * (hash + d*r) mod n
    5. Return (r, s) as the signature
    
    Security note: The nonce k MUST be unique and secret for each signature.
    Reusing k or using a predictable k will compromise the private key.
    """
    # Hash the message
    z = hash_message(message) % n
    
    # Select cryptographically secure random nonce
    while True:
        k = secrets.randbelow(n)
        if k == 0:  # k must not be 0
            continue
            
        # Calculate curve point R = k*G
        R = scalar_multiplication(k, G, p)
        r = R[0] % n
        
        if r == 0:  # r must not be 0
            continue
            
        # Calculate s = k^(-1) * (z + r*d) mod n
        k_inv = pow(k, n-2, n)  # Modular inverse using Fermat's Little Theorem
        s = (k_inv * (z + private_key * r)) % n
        
        if s == 0:  # s must not be 0
            continue
            
        break
    
    return (r, s)

################################################################################
# Step 5: ECDSA Signature Verification
################################################################################

def verify_signature(message, signature, public_key):
    """
    Verify an ECDSA signature against a message and public key
    
    ECDSA verification process:
    1. Check that r and s are in the range [1,n-1]
    2. Hash the message to get z
    3. Calculate u1 = z*s^(-1) mod n and u2 = r*s^(-1) mod n
    4. Calculate the curve point Q = u1*G + u2*Public_Key
    5. The signature is valid if Q_x mod n equals r
    """
    r, s = signature
    
    # Validate signature components
    if not (1 <= r < n and 1 <= s < n):
        print("Signature values out of range")
        return False
        
    # Hash the message
    z = hash_message(message) % n
    
    # Calculate s inverse
    s_inv = pow(s, n-2, n)
    
    # Calculate u1 and u2
    u1 = (z * s_inv) % n
    u2 = (r * s_inv) % n
    
    # Calculate the point Q = u1*G + u2*Public_Key
    P1 = scalar_multiplication(u1, G, p)
    P2 = scalar_multiplication(u2, public_key, p)
    Q = point_addition(P1, P2, p)
    
    if Q is None:  # Point at infinity
        print("Resulting point is at infinity")
        return False
        
    # Verify that Q_x mod n equals r
    return (Q[0] % n) == r

################################################################################
# Step 6: Test ECDSA Implementation
################################################################################

# Generate and verify a signature
message = b"This is a test message for ECDSA signing"
print("Message to sign:", message.decode())

# Sign the message
signature = generate_signature(message, private_key)
r, s = signature
print("\nGenerated ECDSA Signature:")
print(f"r: {hex(r)}")
print(f"s: {hex(s)}")

# Verify the signature
verification_result = verify_signature(message, signature, public_key)
print("\nSignature verification result:", verification_result)

# Test with tampered message
tampered_message = b"This is a TAMPERED message for ECDSA signing"
tampered_verification = verify_signature(tampered_message, signature, public_key)
print("\nTampered message verification (should be False):", tampered_verification)

# Test with tampered signature
tampered_signature = (r, (s + 1) % n)  # Modify s slightly
tampered_sig_verification = verify_signature(message, tampered_signature, public_key)
print("Tampered signature verification (should be False):", tampered_sig_verification)

################################################################################
# Step 7: Demonstrate Bitcoin-style Key Formats (optional)
################################################################################

print("\nBitcoin-style Compressed Public Key:")
# In Bitcoin, public keys are often represented in compressed form
prefix = b'\x02' if public_key[1] % 2 == 0 else b'\x03'  # Even or odd Y coordinate
compressed_pubkey = prefix + public_key[0].to_bytes(32, byteorder='big')
print(f"Compressed public key: {compressed_pubkey.hex()}")

print("\nECDSA Verification Results:")
if verification_result:
    print("✅ SUCCESS: Signature verified correctly!")
    print("   The message is authentic and has not been tampered with.")
else:
    print("❌ FAILURE: Signature verification failed.")

print("\nSecurity Notes:")
print("- Each signature must use a unique, random nonce k")
print("- Reusing k across signatures will leak the private key")
print("- Deterministic ECDSA (RFC 6979) can generate secure k values deterministically")
print("- The private key should never be shared or exposed")