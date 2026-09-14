#Implement ElGamal and Schnorr digital signatures and verify them.
from Crypto.Hash import SHA256
from math import gcd
import secrets

p = 467
g = 2

# Alice's keys
x = secrets.randbelow(p - 2) + 1       # Private key
y = pow(g, x, p)                        # Public key

message = b"Document signed by Alice"

# Convert hash into integer
h = int.from_bytes(
    SHA256.new(message).digest(),
    "big"
) % (p - 1)

# Select k such that gcd(k, p-1) = 1
while True:
    k = secrets.randbelow(p - 2) + 1

    if gcd(k, p - 1) == 1:
        break

# Alice creates signature (r, s)
r = pow(g, k, p)
k_inverse = pow(k, -1, p - 1)
s = ((h - x * r) * k_inverse) % (p - 1)

print("Message  :", message.decode())
print("Signature:", (r, s))

# Bob verifies using Alice's public key
left = pow(g, h, p)
right = (pow(y, r, p) * pow(r, s, p)) % p

if left == right:
    print("ElGamal signature is valid")
else:
    print("ElGamal signature is invalid")