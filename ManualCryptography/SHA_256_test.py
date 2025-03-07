# Calculating SHA-256 hash of "abc" message step by step (64 rounds)

################################################# PRE-PROCESSING (PADDING THE MESSAGE) ################################################################

# Define characters of the message
a = 'a'
b = 'b'
c = 'c'

# Function to convert character to binary
def char_to_binary(char):
    return format(ord(char), '08b')

# Print ASCII to binary values
binary_a = char_to_binary(a)
binary_b = char_to_binary(b)
binary_c = char_to_binary(c)

print(f"Binary value of '{a}': {binary_a}")
print(f"Binary value of '{b}': {binary_b}")
print(f"Binary value of '{c}': {binary_c}")

# Combine binary values
combined_binary = binary_a + binary_b + binary_c
print(f"Combined binary value: {combined_binary}")

# Add single bit '1' to the combined binary string
combined_binary_with_1 = combined_binary + '1'
print(f"Combined binary value with added '1': {combined_binary_with_1}")

# Add enough 0 bits so that the total length is 64 bits less than the multiple of 512 (padding with 0s)
current_length = len(combined_binary_with_1)
total_length = ((current_length + 64) // 512 + 1) * 512 - 64
num_zeros = total_length - current_length
combined_binary_padded = combined_binary_with_1 + '0' * num_zeros
print(f"Combined binary value with padding: {combined_binary_padded}")
print(f"Length of padded binary value: {len(combined_binary_padded)}")

# Calculate the original message length in bits and convert to 64-bit binary
original_message_length = len(a + b + c) * 8
original_message_length_binary = format(original_message_length, '064b')
print(f"Original message length in bits: {original_message_length}")
print(f"64-bit binary representation of original message length: {original_message_length_binary}")

# Append the 64-bit representation of the original message length (resulting in an exactly 1 full block which is 512 bits)
final_binary_message = combined_binary_padded + original_message_length_binary
print(f"Final binary message: {final_binary_message}")
print(f"Length of final binary message: {len(final_binary_message)}")

################################################# INITIALIZE HASH VALUES ################################################################

# Initialize hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
# These constants are part of the SHA-256 specification and serve as "starting fingerprint" for the hash
H = [
    0x6a09e667,  # sqrt(2)
    0xbb67ae85,  # sqrt(3)
    0x3c6ef372,  # sqrt(5)
    0xa54ff53a,  # sqrt(7)
    0x510e527f,  # sqrt(11)
    0x9b05688c,  # sqrt(13)
    0x1f83d9ab,  # sqrt(17)
    0x5be0cd19   # sqrt(19)
]

print(f"Initial hash values: {[hex(h) for h in H]}")


################################################# PROCESSING THE 512-BIT BLOCK ################################################################

# Divide the 512-bit block into sixteen 32-bit words (w0...w15). This is called Message Schedule
W = [final_binary_message[i:i+32] for i in range(0, 512, 32)]

W = [int(word, 2) for word in W]

print(f"Message schedule (W0...W15): {[hex(w) for w in W]}")

# Expand the Message Schedule (W16...W63)
def right_rotate(value, bits):
    return ((value >> bits) | (value << (32 - bits))) & 0xFFFFFFFF

# The W array (message schedule) is expanded from 16 to 64 elements, where each new element is derived from previous elements using bitwise operations
# and modular arithmetic. This process helps in mixing the input data thoroughly, which is crucial for the cryptographic strength of the hash function.
for i in range(16, 64):
    s0 = (right_rotate(W[i-15], 7) ^ right_rotate(W[i-15], 18) ^ (W[i-15] >> 3))
    s1 = (right_rotate(W[i-2], 17) ^ right_rotate(W[i-2], 19) ^ (W[i-2] >> 10))
    W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)

print(f"Expanded message schedule (W0...W63): {[hex(w) for w in W]}")

################################################# COMPRESSION FUNCTION (MAIN LOOP) ################################################################

# Constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Initialize working variables to current hash value
a, b, c, d, e, f, g, h = H

# Main loop
for i in range(64):
    S1 = (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25))
    ch = (e & f) ^ ((~e) & g)
    temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
    S0 = (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22))
    maj = (a & b) ^ (a & c) ^ (b & c)
    temp2 = (S0 + maj) & 0xFFFFFFFF

    h = g
    g = f
    f = e
    e = (d + temp1) & 0xFFFFFFFF
    d = c
    c = b
    b = a
    a = (temp1 + temp2) & 0xFFFFFFFF

# Add the compressed chunk to the current hash value
H = [(x + y) & 0xFFFFFFFF for x, y in zip(H, [a, b, c, d, e, f, g, h])]

################################################# PRODUCE THE FINAL HASH ################################################################

# Produce the final hash value (big-endian)
final_hash = ''.join([format(h, '08x') for h in H])
print(f"SHA-256 hash: {final_hash}")


################################################## VERIFYING THE HASH ################################################################

# Import hashlib for standard SHA-256 implementation
import hashlib

# Original message
original_message = "abc"

# Calculate hash using hashlib
library_hash = hashlib.sha256(original_message.encode()).hexdigest()

# Compare manual calculation with library result
print("\nVerification:")
print(f"Manual SHA-256 hash:  {final_hash}")
print(f"Library SHA-256 hash: {library_hash}")

if final_hash == library_hash:
    print("✅ SUCCESS ❤: Manual implementation matches the library output!")
else:
    print("❌ FAILURE —: Manual implementation does not match the library output.")
    print(f"Difference in hashes: manual vs library")
    for i, (m, l) in enumerate(zip(final_hash, library_hash)):
        if m != l:
            print(f"Position {i}: {m} vs {l}")


