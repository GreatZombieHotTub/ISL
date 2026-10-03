import random

def generate_keys():
    p = 467
    g = 2
    x = random.randint(2, p - 2)
    y = pow(g, x, p)

    return (p, g, y), x

def encrypt(public_key, message):
    p, g, y = public_key
    k = random.randint(2, p - 2)

    c1 = pow(g, k, p)
    c2 = (message * pow(y, k, p)) % p

    return c1, c2

def decrypt(private_key, public_key, ciphertext):
    p, g, y = public_key
    x = private_key
    c1, c2 = ciphertext

    shared = pow(c1, x, p)
    message = (c2 * pow(shared, -1, p)) % p

    return message

def homomorphic_multiply(c1, c2, public_key):
    p, g, y = public_key

    return (
        (c1[0] * c2[0]) % p,
        (c1[1] * c2[1]) % p
    )

public_key, private_key = generate_keys()

a = 7
b = 3

ciphertext_a = encrypt(public_key, a)
ciphertext_b = encrypt(public_key, b)

encrypted_product = homomorphic_multiply(
    ciphertext_a,
    ciphertext_b,
    public_key
)

result = decrypt(private_key, public_key, encrypted_product)

print("Ciphertext of 7:", ciphertext_a)
print("Ciphertext of 3:", ciphertext_b)
print("Encrypted product:", encrypted_product)
print("Decrypted product:", result)
print("Expected product:", a * b)