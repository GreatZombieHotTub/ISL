import numpy as np


def text_to_vectors(text):
    # Remove spaces/special characters and convert to uppercase
    clean_text = "".join([c for c in text.upper() if c.isalpha()])

    # Hill Cipher works on fixed-size blocks of 2 letters.
    # If the message length is odd, add X as padding.
    if len(clean_text) % 2 != 0:
        clean_text += "X"

    vectors = []

    # Process plaintext two letters at a time
    for i in range(0, len(clean_text), 2):
        char1 = clean_text[i]
        char2 = clean_text[i + 1]

        # Convert letters to numbers: A=0, B=1, ..., Z=25
        v = [
            ord(char1) - ord("A"),
            ord(char2) - ord("A")
        ]

        vectors.append(v)

    return clean_text, vectors


def hill_encrypt(plaintext, key_matrix):
    # Convert plaintext into pairs of numbers
    clean_text, vectors = text_to_vectors(plaintext)

    # Convert key into a NumPy matrix for multiplication
    K = np.array(key_matrix)

    ciphertext_nums = []

    # Encrypt each 2-letter block separately
    for v in vectors:

        # Convert the pair into a 2x1 column matrix
        P = np.array(v).reshape(2, 1)

        # Hill Cipher formula:
        # C = K × P (mod 26)
        C = np.dot(K, P) % 26

        # Store the resulting numbers
        ciphertext_nums.extend(C.flatten())

    # Convert numbers back to letters
    # 0=A, 1=B, ..., 25=Z
    ciphertext = "".join(
        [chr(num + ord("A")) for num in ciphertext_nums]
    )

    return clean_text, ciphertext


def main():
    # Plaintext message
    message = "We live in an insecure world"

    # 2x2 Hill Cipher key matrix
    key = [
        [3, 3],
        [2, 7]
    ]

    # Encrypt the message
    clean_text, ciphertext = hill_encrypt(message, key)

    # Display results
    print("=" * 50)
    print("           HILL CIPHER ENCRYPTION")
    print("=" * 50)
    print("Original Message:  ", message)
    print("Prepared Text:     ", clean_text)
    print("Ciphertext:        ", ciphertext)


# Program starts here
if __name__ == "__main__":
    main()

"""# Hill Cipher:
# Encryption: C = K × P (mod 26)
# Decryption: P = K^(-1) × C (mod 26)

# For K = [[a, b], [c, d]]:
# det(K) = ad - bc
# K is invertible only if gcd(det(K), 26) = 1
# Find det(K)^(-1) mod 26
#
# K^(-1) = det(K)^(-1) × [[d, -b], [-c, a]] mod 26"""

"""for key
# Key = [[3, 3], [2, 7]]
# det(K) = 3×7 - 3×2 = 15
# gcd(15, 26) = 1 → valid key
# 15^(-1) mod 26 = 7
# Therefore K^(-1) = [[23, 5], [12, 21]]"""
