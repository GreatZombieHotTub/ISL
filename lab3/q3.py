import random

# -----------------------------
# ELGAMAL KEY GENERATION
# -----------------------------

# Prime number
p = 467

# Generator
g = 2

# Private key
x = 127

# Public key component
y = pow(g, x, p)

print("Public Key :", (p, g, y))
print("Private Key:", x)

# -----------------------------
# MESSAGE
# -----------------------------

message = "Confidential Data"

# Convert characters to integers
plaintext = [ord(ch) for ch in message]

# -----------------------------
# ENCRYPTION
# -----------------------------

ciphertext = []

for m in plaintext:

    # Random value
    k = random.randint(1, p - 2)

    # First ciphertext component
    c1 = pow(g, k, p)

    # Second ciphertext component
    c2 = (m * pow(y, k, p)) % p

    ciphertext.append((c1, c2))

print("\nOriginal Message :", message)
print("Ciphertext       :", ciphertext)

# -----------------------------
# DECRYPTION
# -----------------------------

decrypted = []

for c1, c2 in ciphertext:

    # Calculate shared value
    s = pow(c1, x, p)

    # Calculate modular inverse
    s_inverse = pow(s, -1, p)

    # Recover message
    m = (c2 * s_inverse) % p

    decrypted.append(m)

# Convert integers to characters
decrypted_message = ''.join(chr(m) for m in decrypted)

print("Decrypted Message:", decrypted_message)