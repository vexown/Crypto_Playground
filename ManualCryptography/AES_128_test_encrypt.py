####### Step by step manual implementation of the AES-128 algorithm in ECB Mode (no IV) ######

from Crypto.Cipher import AES # used only for verification at the end, manual implementation WITHOUT library is implemented below
from Crypto.Random import get_random_bytes

# Helper functions, you can skip them:
# Initialize state in column-major order
def create_state_array(data):
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = data[j*4 + i]
    return state

# Convert state back to bytes in column-major order
def state_to_bytes(state):
    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[j*4 + i] = state[i][j]
    return bytes(result)

def print_state(state, round_num=None):
    if round_num is not None:
        print(f"State Array - State after Round {round_num}:")
    else:
        print("State Array:")
    for row in state:
        print(" ".join(f"{byte:02x}" if isinstance(byte, int) else byte for byte in row))
    print()

#################################### AES Encryption Process ################################

# Start
#   Key Generation
#       Generate a random 16-byte (128-bit) key for AES-128 encryption.
#    Key Expansion
#       Expand the 16-byte key into a series of round keys using the S-Box and Rcon array.
#    Initial Round
#        AddRoundKey: XOR the plaintext with the first round key.
#        Main Rounds (repeated 9 times for AES-128)
#        SubBytes: Substitute each byte using the S-Box.
#        ShiftRows: Shift rows of the state array.
#       MixColumns: Mix the columns of the state array.
#        AddRoundKey: XOR the state with the round key.
#   Final Round
#        SubBytes
#        ShiftRows
#        AddRoundKey
# Final Encryption Output
#   The resulting state array is the ciphertext.

#################################### STEP 1 - Key Generation ################################

# In AES encryption, the key is essentially a random number. However, there are specific requirements regarding the key:
#   Length: The key length must match the AES variant you are using. For AES-128, the key must be 16 bytes (128 bits). 
#           For AES-192 and AES-256, the key lengths must be 24 bytes (192 bits) and 32 bytes (256 bits), respectively.
#   Randomness: The key should be generated using a cryptographically secure random number generator to ensure its unpredictability.
#
# Generate a random 16-byte (128-bit) key for AES-128 encryption
key = get_random_bytes(16)
print(f"Generated AES key: {key.hex()}")

# Define the AES S-Box and Rcon array
# The AES S-Box (Substitution Box) and the Rcon (Round Constant) array are fundamental components used in the AES encryption algorithm.

# AES S-box
# The S-Box is a substitution table used in the SubBytes step of the AES algorithm. 
# It is a 16x16 matrix that contains a permutation of all 256 possible 8-bit values. 
# The S-Box is designed to provide non-linearity and confusion in the cipher. 
# Each byte of the state array is replaced with the corresponding value from the S-Box.
s_box = [
    # 0     1    2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# AES Rcon (round constant) array
# The Rcon array is used in the key expansion process. 
# It contains round constants that are used to derive the round keys from the original key
rcon = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]

# The key expansion function generates the round keys from the original key using the S-Box and Rcon array.
#   The initial key schedule is created. The "key schedule" is a series of round keys derived from the original encryption key.
#       Initial Key: The original key provided for encryption (e.g., a 16-byte key for AES-128).
#       Round Keys: Derived keys used in each round of the AES encryption process. For AES-128, there are 10 rounds, 
#                   so 11 round keys are generated (including the one from initial key). Each round key is 16bytes divided into 4 words.
#   For each subsequent round key, the previous key is transformed using the S-Box and Rcon array.
#   The transformed key is XORed with the key from four positions earlier to generate the new round key.
def key_expansion(key):
    # Initialize the key schedule with the original key (the initial round key, in a form of four 4-byte words, 16 bytes total)
    key_schedule = [list(key[i:i+4]) for i in range(0, len(key), 4)]
    
    # Generate the remaining round keys (we need 11 and we have just the initial 1 right now)
    for i in range(4, 44):
        temp = key_schedule[i - 1]
        if i % 4 == 0:
            temp = [s_box[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= rcon[i // 4]
        key_schedule.append([key_schedule[i - 4][j] ^ temp[j] for j in range(4)])
    
    return key_schedule

key_schedule = key_expansion(key)
print("Key Schedule:")
for i in range(11):
    round_key = key_schedule[i*4:(i+1)*4]
    hex_round_key = [[f"{byte:02x}" for byte in word] for word in round_key]
    print(f"Round {i}: {hex_round_key}")


#################################### STEP 2 - Initial Round ################################

# Initial Round
# In the initial round, we perform only one step:
#       AddRoundKey: XOR the plaintext with the first round key.

# Prepare the plaintext
# The plaintext is the data that we want to encrypt. In this example, we will use the plaintext
# "This is secret" and pad it to be a multiple of the block size (16 bytes) using PKCS#7 padding.
# The plaintext is then converted to a state array (a 4x4 matrix) for processing.

# Function to handle PKCS#7 padding
def pad(plaintext):
    padding_len = 16 - (len(plaintext) % 16)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

# Define the plaintext to be encrypted (and pad it to be 16 bytes which is the block size (128bits) for all AES)
# Don't try to use a plaintext with exactly 16 bytes, apparently padding is always required so that will cause a need to have a second block
# (as least that's what I remember)
plaintext = b'This is secret'
plaintext = pad(plaintext)
print("plaintext: ")
print(plaintext)

# Convert plaintext to a list of integers (state array)
state = create_state_array(plaintext)
print("State Array - State before AddRoundKey (plaintext converted to hex bytes):")
print_state(state)

def add_round_key(state, round_key):
    # Flatten the round key into a 1D array
    flat_key = [byte for word in round_key for byte in word]
    for i in range(4):
        for j in range(4):
            # Apply in column-major order
            state[i][j] ^= flat_key[j*4 + i]
    return state

# AddRoundKey: XOR the plaintext with the first round key
state = add_round_key(state, key_schedule[:4])

print("State Array - State after AddRoundKey:")
print_state(state)

#################################### STEP 3 - Main Rounds ################################

# Main Rounds
# In the main rounds, we perform the following steps for each of the 9 main rounds (for AES-128). 
# For AES-192 (the number means the key length) it is 11 main rounds, and for AES-256 you have 13 main rounds
# Remember that there is also the final round after the main rounds which is the same as the main rounds but without the MixColumns step.
#
# The main rounds consist of the following steps:
#       SubBytes: Substitute each byte using the S-Box.
#       ShiftRows: Shift rows of the state array.
#       MixColumns: Mix the columns of the state array. 
#       AddRoundKey: XOR the state with the round key.
#
# SubBytes
#       The SubBytes step substitutes each byte in the state array with the corresponding value from the S-Box.
#
# ShiftRows
#       The ShiftRows step shifts the rows of the state array. The first row is not shifted, the second row is shifted left by one byte, 
#       the third row by two bytes, and the fourth row by three bytes.
#
# MixColumns
#       The MixColumns step mixes the columns of the state array using a fixed polynomial.
#
# AddRoundKey
#       The AddRoundKey step XORs the state with the round key.

def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]
    return state

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]
    return state

#helper function for mix_columns
def gmul(a, b):
    p = 0
    hi_bit_set = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mix_columns(state):
    # Create a new state to avoid modifying while iterating
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    
    for j in range(4):  # For each column
        column = [state[i][j] for i in range(4)]  # Extract column j
        
        # Mix column
        new_state[0][j] = gmul(column[0], 2) ^ gmul(column[1], 3) ^ gmul(column[2], 1) ^ gmul(column[3], 1)
        new_state[1][j] = gmul(column[0], 1) ^ gmul(column[1], 2) ^ gmul(column[2], 3) ^ gmul(column[3], 1)
        new_state[2][j] = gmul(column[0], 1) ^ gmul(column[1], 1) ^ gmul(column[2], 2) ^ gmul(column[3], 3)
        new_state[3][j] = gmul(column[0], 3) ^ gmul(column[1], 1) ^ gmul(column[2], 1) ^ gmul(column[3], 2)
    
    return new_state

for round in range(1, 10): # Perform the main 9 rounds
    state = sub_bytes(state)
    state_after_sub_bytes = state
    print(f"State Array - State after SubBytes (Round {round}):")
    print_state(state_after_sub_bytes)

    state = shift_rows(state)
    state_after_shift_rows = state
    print(f"State Array - State after ShiftRows (Round {round}):")
    print_state(state_after_shift_rows)

    state = mix_columns(state)
    state_after_mix_columns = state
    print(f"State Array - State after MixColumns (Round {round}):")
    print_state(state_after_mix_columns)

    round_key = key_schedule[round*4:(round+1)*4]
    state = add_round_key(state, round_key)
    state_after_add_round_key = state
    print(f"State Array - State after AddRoundKey (Round {round}):")
    print_state(state_after_add_round_key)

print("State Array - State after Main Rounds:")
hex_state_main_rounds = [[f"{byte:02x}" for byte in word] for word in state]
print_state(hex_state_main_rounds)

#################################### STEP 4 - Final Round ################################

# Final Round is done the same as normal rounds EXCEPT WITHOUT mix_columns
state = sub_bytes(state)
print("State Array - State after SubBytes (Final Round):")
print_state(state)

state = shift_rows(state)
print("State Array - State after ShiftRows (Final Round):")
print_state(state)

round_key = key_schedule[10*4:(10+1)*4]
state = add_round_key(state, round_key)
print("State Array - State after AddRoundKey (Final Round):")
print_state(state)

#################################### Final Encryption Output ################################

# The resulting state array is the ciphertext
ciphertext = state_to_bytes(state)
print("Ciphertext:")
print(ciphertext.hex())

#################################### VERIFICATION ################################

# Verify the output using the AES library
cipher = AES.new(key, AES.MODE_ECB)
library_ciphertext = cipher.encrypt(plaintext)
print("Library Ciphertext:")
print(library_ciphertext.hex())

# Compare the outputs
if ciphertext == library_ciphertext:
    print("Verification successful: The outputs match.")
else:
    print("Verification failed: The outputs do not match.")