################################################################################
# RSA (Rivest-Shamir-Adleman) Cryptosystem Implementation
################################################################################
# WHAT IS RSA:
#   RSA is an asymmetric cryptographic algorithm that uses a pair of keys:
#   - A public key for encryption (shared openly)
#   - A private key for decryption (kept secret)
#   Its security is based on the mathematical difficulty of factoring large numbers.
#   (Factoring is the process of finding prime numbers that multiply to a given number,
#    for example, finding p and q given n = p * q where p and q are prime)
#
# USEFUL APPLICATIONS:
#   - Digital signatures for document authentication
#   - Secure key exchange over insecure channels (by encrypting a symmetric key, e.g AES)
#       This is used in protocols like TLS, PGP and secure email
#       So instead of using RSA to encrypt the entire message, it's used to encrypt 
#       a symmetric key (e.g AES key) which is then used to encrypt the actual message.
#   - Small-volume secure communications
#   - Certificate authorities and PKI infrastructure
#
# WHERE RSA SHOULD NOT BE USED:
#   - Encrypting large volumes of data (use symmetric encryption instead)
#          This is due to RSA's slow encryption/decryption speed compared to symmetric ciphers
#   - Modern applications requiring post-quantum security
#   - When forward secrecy is required (compromised private key exposes all past messages)
#   - Resource-constrained environments (computationally expensive)
#   - Without proper padding schemes in production (vulnerable to various attacks)
#   - Direct encryption of passwords or low-entropy data (because of deterministic encryption)
#           It is better to use a key derivation function (KDF) to derive a symmetric key from a password
#           and then encrypt the data with a symmetric cipher like AES. Or use a password hashing function.
################################################################################

################################################################################
# Manual implementation of RSA encryption/decryption algorithm
################################################################################
# Note - This is a simplified version of RSA for educational purposes.
# In practice, RSA encryption should always use padding schemes like OAEP or PKCS1v15.
# In this case we do not use padding for simplicity, but it is essential for security.
################################################################################
import random
import math
from Crypto.Util.number import getPrime  # Used only for prime generation
from Crypto.PublicKey import RSA  # Only used for verification at the end

print("RSA Manual Implementation Test")
print("=" * 50)

################################################################################
# Step 1: Generate RSA Key Pair
################################################################################

def gcd(a, b):
    """Calculate greatest common divisor of a and b"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find coefficients x,y such that ax + by = gcd(a,b)"""
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    """Calculate the modular inverse of a mod m"""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# RSA KEY SIZE & PRIME SELECTION:
# 
# 1. KEY SIZE:
#    - RSA key size = bit length of modulus n (product of p and q)
#    - If p and q are both k-bit primes, n will be approximately 2k bits
#    - In this example: 512-bit primes → ~1024-bit RSA key
#    - Current security standards (2025): 2048-bit minimum (1024-bit primes)
#    
# 2. PRIME PROPERTIES:
#    - LARGE: Must be sufficiently large to resist factoring attacks
#    - RANDOM: Selected using cryptographically secure random number generation
#    - SIMILAR BIT-LENGTH: p and q should have roughly the same size
#    - SUFFICIENT DIFFERENCE: |p-q| should be large to prevent Fermat factorization
#    - PRIME FACTORS: In strong primes, (p-1) and (p+1) have large prime factors
#    
# 3. SECURITY CONSIDERATIONS:
#    - Larger primes = more security but slower operations
#    - Both (p-1) and (q-1) must be coprime to the public exponent e
#    - Never reuse primes across different keys
#    - The security of RSA relies entirely on keeping these primes secret

# Generate two large prime numbers p and q
print("Generating two random prime numbers p and q...")
p = getPrime(512)  # 512-bit prime number
q = getPrime(512)  # 512-bit prime number

# Calculate n = p * q (modulus)
n = p * q
print(f"p = {p}")
print(f"q = {q}")
print(f"n = p * q = {n}")

# Knowing p and q, we can calculate Euler's totient function: φ(n) = (p-1) * (q-1)
# It represents the count of numbers less than n that are coprime to n
phi_n = (p - 1) * (q - 1)

print(f"φ(n) = (p-1) * (q-1) = {phi_n}")

# Choose public exponent e
# This is part of the public key and must be coprime with φ(n)
# It's a small number, typically 3 or 65537 (2^16 + 1) for faster encryption
# Used for encryption: 
#                       c = m^e mod n (m = message, c = ciphertext)
# Also used to calculate the private exponent d
e = 65537
print(f"Public exponent e = {e}")

# Now we have the Public key which is represented as (n, e)
print(f"\nPublic key (n, e): ({n}, {e}) \n")

# Check if e and φ(n) are coprime
if gcd(e, phi_n) != 1:
    raise ValueError("e and φ(n) must be coprime")

# Calculate private exponent d such that (d * e) % φ(n) = 1
# This is part of the private key
# It's a large number, roughly the same size as modulus n
# Used for decryption: 
#                       m = c^d mod n (c = ciphertext, m = message)
d = mod_inverse(e, phi_n)

print(f"Private exponent d = {d}")
print(f"Verification: (d * e) % φ(n) = {(d * e) % phi_n}")
print()

# Now we have the Private key which is represented as (n, d)
print(f"\nPrivate key (n, d): ({n}, {d}) \n")

################################################################################
# Step 2: Manual RSA Encryption
################################################################################

def manual_rsa_encrypt(message_int, e, n):
    """Encrypt a message using RSA: c = m^e mod n"""
    # pow is Python's built-in function for efficient modular exponentiation
    # pow(x, y, z) computes x^y mod z
    # so in this case, it calculates message_int^e mod n
    return pow(message_int, e, n)

def manual_rsa_decrypt(ciphertext_int, d, n):
    """Decrypt a message using RSA: m = c^d mod n"""
    # pow is Python's built-in function for efficient modular exponentiation
    # pow(x, y, z) computes x^y mod z
    # so in this case, it calculates ciphertext_int^d mod n
    return pow(ciphertext_int, d, n)


# Test message (plaintext)
# Note: In practice, RSA is not used to directly encrypt messages, but to encrypt symmetric keys
# which are then used to encrypt the actual message.
# This is because RSA encryption is slow and has size limitations.
# For demonstration purposes, we will encrypt a simple message here.
################################################################################
# RSA MESSAGE SIZE LIMITATIONS
################################################################################
# 
# RSA MAXIMUM MESSAGE SIZE:
#   - The numerical value of the message MUST be less than the modulus n
#   - For a 2048-bit RSA key, theoretical maximum is ~256 bytes
#   - With proper padding (required for security), usable size is even smaller (~245 bytes)
#
# WHAT HAPPENS IF MESSAGE > MODULUS?
#   - Mathematical failure: The encryption function won't produce uniquely decodable results
#   - Decryption will fail: Original message cannot be recovered correctly
#   - Most implementations either throw an error or silently truncate (dangerous!)
#
# SOLUTIONS FOR LARGER MESSAGES:
#   1. Block-based approach (rarely used):
#      - Split message into smaller chunks, each < n
#      - Encrypt each chunk separately
#      - Complex to implement correctly with proper padding
#
#   2. Hybrid encryption (industry standard):
#      - Generate random symmetric key (e.g., 32-byte AES key)
#      - Encrypt large message with AES (fast, no size limit)
#      - Encrypt only the small AES key with RSA
#      - Transmit both the RSA-encrypted key and AES-encrypted data
#
#   This is why RSA is almost never used directly for message encryption in
#   real applications, but rather as part of a hybrid cryptosystem.
################################################################################
################################################################################
# RSA PADDING SCHEMES
################################################################################
#
# THIS IMPLEMENTATION: NO PADDING ("TEXTBOOK RSA")
#   - We're using raw RSA formulas: c = m^e mod n and m = c^d mod n
#   - This is called "textbook RSA" - great for learning but INSECURE in practice
#   - Vulnerable to several attacks including: chosen-ciphertext, small message,
#     and malleability attacks
#   - Does not provide confidentiality, integrity, or authenticity guarantees
#   - Should NEVER be used in real systems without proper padding
#   - The size of the message is limited by the size of the modulus n
#
# WHY RSA NEEDS PADDING:
#   1. Deterministic output: Without padding, same message always encrypts to same ciphertext
#   2. Malleability: The homomorphic property we demonstrated can be exploited by attackers
#   3. Small message attacks: If m is small, attacker can find m by calculating the eth root of c
#   4. Chosen-ciphertext vulnerability: Especially with low public exponents (e.g., 3)
#
# COMMON RSA PADDING SCHEMES:
#
#   1. PKCS#1 v1.5 Padding:
#      - Structure: [00][02][random non-zero bytes][00][message]
#      - Oldest standardized scheme (from 1993)
#      - Still widely used despite known vulnerabilities
#      - Maximum message size: ~245 bytes for 2048-bit RSA key (11 bytes overhead)
#
#   2. OAEP (Optimal Asymmetric Encryption Padding):
#      - Modern, recommended approach
#      - Uses hash functions and mask generation functions
#      - Provably secure under certain assumptions
#      - More complex structure with random seed values and hash outputs
#      - Maximum message size: ~190 bytes for 2048-bit RSA key with SHA-256 (66 bytes overhead)
#
#   3. PSS (Probabilistic Signature Scheme):
#      - Used specifically for RSA signatures
#      - More secure than older signature padding methods
#
# IN PRODUCTION:
#   - Always use a well-tested library implementation of RSA
#   - Never implement padding yourself due to security subtleties
#   - OAEP is the current recommended padding scheme for encryption
################################################################################
message = "Hello, RSA!"

# Message Conversion for RSA
# 
# Converting a string to an integer is necessary because RSA operates on numbers:
#
# Process:
# 1. String to bytes conversion:
#    - message.encode() converts the string "Hello, RSA!" to its UTF-8 byte representation
#    - Each character is converted to one or more bytes (ASCII chars = 1 byte each)
#    - For "Hello, RSA!" this produces bytes [72, 101, 108, 108, 111, 44, 32, 82, 83, 65, 33]
#
# 2. Bytes to integer conversion:
#    - int.from_bytes(..., 'big') treats the byte array as one large number
#    - 'big' means big-endian (most significant byte first), like reading left-to-right
#    - Mathematically equivalent to: 72×256¹⁰ + 101×256⁹ + 108×256⁸ + ... + 33×256⁰
#
# This produces a unique integer for any message, and the process can be reversed after
# decryption by using .to_bytes() followed by .decode() to recover the original string.
message_int = int.from_bytes(message.encode(), 'big')
print(f"Original message: '{message}'")
print(f"Message as integer: {message_int}")

# Encrypt the message
ciphertext = manual_rsa_encrypt(message_int, e, n)
print(f"\nEncrypted ciphertext: {ciphertext}\n")

# Decrypt the message
decrypted_int = manual_rsa_decrypt(ciphertext, d, n)
decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')
decrypted_message = decrypted_bytes.decode()
print(f"\nDecrypted message: '{decrypted_message}'\n")
print()

################################################################################
# Step 3: Demonstration of RSA Properties
################################################################################

print("Demonstrating RSA mathematical properties:")
print(f"1. Encryption followed by decryption gives original message: {decrypted_message == message}")

# Show that RSA is multiplicatively homomorphic.
#   A cryptosystem is homomorphic if you can perform certain operations on encrypted data without decrypting it first. 
#   With RSA specifically:
#       If you encrypt two messages separately and multiply the resulting ciphertexts, 
#       the result will decrypt to the product of the original messages.
#  This property has practical applications in:
#       Privacy-preserving computations
#       Digital voting systems
#       Financial protocols where calculations on encrypted values are needed
#       Zero-knowledge proofs
print("\nDemonstrating RSA homomorphic property:")

# Encrypt two messages separately
m1 = 42
m2 = 73
c1 = manual_rsa_encrypt(m1, e, n)
c2 = manual_rsa_encrypt(m2, e, n)

# Multiply the ciphertexts together to produce a new ciphertext (c_product)
c_product = (c1 * c2) % n

# Decrypt the product of the ciphertexts - this should be equal to the product of the original messages
m_product = manual_rsa_decrypt(c_product, d, n)
print(f"m1 = {m1}, m2 = {m2}")
print(f"encrypt(m1) * encrypt(m2) mod n = {c_product}")
print(f"decrypt(c_product) = {m_product}")
print(f"m1 * m2 = {m1 * m2}")
print(f"Homomorphic property holds: {m_product == (m1 * m2) % n}")
print()

################################################################################
# Step 4: Verification using PyCryptodome library
################################################################################

print("Verifying with PyCryptodome library:")
# Generate RSA key pair using library
key = RSA.construct((n, e, d))

# Create simple test message
test_message = b"Test message for verification"
test_int = int.from_bytes(test_message, 'big')

# Manual encryption/decryption
manual_cipher = manual_rsa_encrypt(test_int, e, n)
manual_decrypted = manual_rsa_decrypt(manual_cipher, d, n)
manual_result = manual_decrypted.to_bytes((manual_decrypted.bit_length() + 7) // 8, 'big')

print(f"Original: {test_message}")
print(f"Manual decryption result: {manual_result}")
print(f"Verification: {test_message == manual_result}")