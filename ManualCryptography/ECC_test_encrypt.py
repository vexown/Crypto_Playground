################################################################################
# ECIES (Elliptic Curve Integrated Encryption Scheme) Implementation
################################################################################
# This script demonstrates a manual implementation of ECIES, a hybrid encryption
# scheme using ECC + ECDH + AES + HMAC.
# 
# ECIES provides a secure method for encrypting messages using the recipient's public key.
#
# ECIES is widely used in blockchain technologies, secure messaging apps, and IoT devices
# due to its efficiency, security, and perfect forward secrecy. It combines the benefits
# of asymmetric and symmetric encryption schemes to provide a robust security solution.
#
# Overview:
# - Uses NIST P-256 curve parameters
# - Implements core ECC operations (point addition, doubling, scalar multiplication)
# - Demonstrates complete ECIES workflow (key generation, encryption, decryption)
#
# ECIES Security Components:
# 1. Asymmetric Part (ECC):
#    - Generates a random ephemeral key pair for each encryption
#    - Uses ECDH (Elliptic Curve Diffie-Hellman) to create a shared secret
#    - Provides perfect forward secrecy through ephemeral keys
#
# 2. Symmetric Part:
#    - KDF (Key Derivation Function) using PBKDF2 to derive encryption and MAC keys
#    - AES-128-CBC for data encryption
#    - HMAC-SHA256 for message authentication
#    - PKCS#7 padding for block cipher compatibility
#
# ECIES Workflow:
# 1. Encryption:
#    - Generate ephemeral key pair
#    - Compute shared secret point using recipient's public key
#    - Derive encryption and MAC keys from shared secret
#    - Encrypt plaintext with AES
#    - Generate MAC for authenticated encryption
#
# 2. Decryption:
#    - Compute same shared secret using recipient's private key and ephemeral public key
#    - Derive identical encryption and MAC keys
#    - Verify MAC to ensure data integrity
#    - Decrypt ciphertext to recover original message
#
# Security depends on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
# Given points P and Q=kP, it's computationally infeasible to determine k.
################################################################################
import os
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

################################################################################
# Step 1: Define the elliptic curve parameters
################################################################################
# We'll use a simplified version of the NIST P-256 curve for demonstration
# y² = x³ - 3x + b (mod p) where b is defined below

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
print(f"Base point G = ({Gx}, {Gy})")
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
import secrets
private_key = secrets.randbelow(n)
# Compute public key Q = private_key * G
public_key = scalar_multiplication(private_key, G, p)

print("Key Generation:")
print(f"Private key: {hex(private_key)}")
print(f"Public key: ({hex(public_key[0])}, {hex(public_key[1])})")
print()

################################################################################
# Step 4: ECIES Encryption - Manual Implementation
################################################################################

    
# Key Derivation Function using PBKDF2-HMAC-SHA256
#
# This function converts the elliptic curve point (shared secret from ECDH)
# into cryptographically strong key material for encryption and authentication.
#
# Why KDF is necessary:
# - Raw EC points aren't suitable for direct use as cryptographic keys
# - KDF provides uniform distribution and proper entropy
# - Separate keys needed for encryption (AES) and authentication (HMAC)
#
# Process:
# 1. Convert EC point coordinates to bytes
# 2. Apply PBKDF2 with SHA-256 to derive key material
# 3. Use salt to prevent precomputation attacks
# 4. Use iterations (1000) to increase computational cost
#
# Returns a derived key of specified length (default 32 bytes - 16 for encryption, 16 for MAC)
#
def kdf(shared_secret, salt, key_length=32):
    """Key Derivation Function using HKDF"""
    # Convert point coordinates to bytes for KDF input
    secret_bytes = shared_secret[0].to_bytes((shared_secret[0].bit_length() + 7) // 8, byteorder='big')
    secret_bytes += shared_secret[1].to_bytes((shared_secret[1].bit_length() + 7) // 8, byteorder='big')
    
    derived_key = hashlib.pbkdf2_hmac('sha256', secret_bytes, salt, iterations=1000, dklen=key_length)
    return derived_key

def encrypt_manual(plaintext, recipient_public_key):
    """Manually encrypt using ECIES scheme"""
    
    # 1. Generate ephemeral key pair
    ephemeral_private_key = secrets.randbelow(n)
    ephemeral_public_key = scalar_multiplication(ephemeral_private_key, G, p)
    
    # 2. Compute shared secret with ECDH
    shared_point = scalar_multiplication(ephemeral_private_key, recipient_public_key, p)
    
    # 3. Derive symmetric encryption key using KDF
    salt = os.urandom(16)
    key_material = kdf(shared_point, salt)
    enc_key = key_material[:16]  # First 16 bytes for AES-128
    mac_key = key_material[16:]  # Last 16 bytes for HMAC
    
    # 4. Encrypt plaintext with AES-128 in CBC mode
    iv = os.urandom(16)
    padded_plaintext = pad_message(plaintext)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # 5. Compute MAC
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    
    # Return components needed for decryption
    return {
        'ephemeral_public_key': ephemeral_public_key,
        'iv': iv,
        'ciphertext': ciphertext,
        'mac': mac,
        'salt': salt
    }

def pad_message(message):
    """PKCS#7 padding"""
    block_size = 16
    padding_length = block_size - (len(message) % block_size)
    padding = bytes([padding_length] * padding_length)
    return message + padding

# Encrypt a message
message = b"This is a secret ECC message"
print("Original message:", message.decode())

encryption_result = encrypt_manual(message, public_key)
print("\nManual ECIES Encryption:")
print(f"Ephemeral public key: ({hex(encryption_result['ephemeral_public_key'][0])}, {hex(encryption_result['ephemeral_public_key'][1])})")
print(f"IV: {encryption_result['iv'].hex()}")
print(f"Ciphertext: {encryption_result['ciphertext'].hex()}")
print(f"MAC: {encryption_result['mac'].hex()}")
print(f"Salt: {encryption_result['salt'].hex()}")
print()

################################################################################
# Step 5: ECIES Decryption - Manual Implementation
################################################################################

def unpad_message(padded_message):
    """Remove PKCS#7 padding"""
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]

def decrypt_manual(encryption_result, private_key):
    """Manually decrypt using ECIES scheme"""
    
    # 1. Extract encryption components
    ephemeral_public_key = encryption_result['ephemeral_public_key']
    iv = encryption_result['iv']
    ciphertext = encryption_result['ciphertext']
    mac = encryption_result['mac']
    salt = encryption_result['salt']
    
    # 2. Compute shared secret with ECDH
    shared_point = scalar_multiplication(private_key, ephemeral_public_key, p)
    
    # 3. Derive symmetric encryption key using KDF
    key_material = kdf(shared_point, salt)
    enc_key = key_material[:16]
    mac_key = key_material[16:]
    
    # 4. Verify MAC
    computed_mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(computed_mac, mac):
        raise ValueError("MAC verification failed")
    
    # 5. Decrypt ciphertext
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 6. Remove padding
    decrypted = unpad_message(decrypted_padded)
    
    return decrypted

# Decrypt the message
decrypted_message = decrypt_manual(encryption_result, private_key)
print("Manual decryption result:", decrypted_message.decode())
print()

################################################################################
# Step 6: Verify Manual Implementation
################################################################################

print("\nVerification Results:")
if message == decrypted_message:
    print("✅ SUCCESS: Manual implementation correctly encrypted and decrypted the message!")
    print(f"Original message: '{message.decode()}'")
    print(f"Decrypted message: '{decrypted_message.decode()}'")
else:
    print("❌ FAILURE: Manual decryption did not match the original message.")
    print(f"Original message: '{message.decode()}'")
    print(f"Decrypted message: '{decrypted_message.decode()}'")
    # Show detailed differences if they don't match
    for i, (orig, dec) in enumerate(zip(message, decrypted_message)):
        if orig != dec:
            print(f"  Difference at position {i}: {chr(orig)} vs {chr(dec)}")



