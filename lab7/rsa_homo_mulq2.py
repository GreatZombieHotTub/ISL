def generate_keys():
    p = 61
    q = 53

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 17
    d = pow(e, -1, phi)

    return (n, e), (n, d)


def encrypt(public_key, message):
    n, e = public_key
    return pow(message, e, n)


def decrypt(private_key, ciphertext):
    n, d = private_key
    return pow(ciphertext, d, n)


def homomorphic_multiply(c1, c2, public_key):
    n, e = public_key
    return (c1 * c2) % n


# Generate keys
public_key, private_key = generate_keys()

# Original integers
a = 7
b = 3

# Encrypt both integers
c1 = encrypt(public_key, a)
c2 = encrypt(public_key, b)

# Multiply ciphertexts without decrypting them
encrypted_product = homomorphic_multiply(c1, c2, public_key)

# Decrypt and verify the product
result = decrypt(private_key, encrypted_product)

print("Ciphertext of 7:", c1)
print("Ciphertext of 3:", c2)
print("Encrypted product:", encrypted_product)
print("Decrypted product:", result)
print("Expected product:", a * b)
print("Products match:", result == a * b)
