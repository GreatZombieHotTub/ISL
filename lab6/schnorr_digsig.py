from Crypto.Hash import SHA256
import secrets

# Small values for demonstration
p = 23
q = 11
g = 4

# Alice's keys
x = secrets.randbelow(q - 1) + 1
y = pow(g, x, p)

message = b"Document signed by Alice"

# Alice signs
k = secrets.randbelow(q - 1) + 1
r = pow(g, k, p)

e_data = message + r.to_bytes(
    (r.bit_length() + 7) // 8,
    "big"
)

e = int.from_bytes(
    SHA256.new(e_data).digest(),
    "big"
) % q

s = (k + x * e) % q

print("Message  :", message.decode())
print("Signature:", (e, s))

# Bob verifies
y_inverse_e = pow(
    pow(y, e, p),
    -1,
    p
)

r_verify = (
    pow(g, s, p) * y_inverse_e
) % p

e_data_verify = message + r_verify.to_bytes(
    (r_verify.bit_length() + 7) // 8,
    "big"
)

e_verify = int.from_bytes(
    SHA256.new(e_data_verify).digest(),
    "big"
) % q

if e == e_verify:
    print("Schnorr signature is valid")
else:
    print("Schnorr signature is invalid")