import numpy as np


def text_to_vectors(text):
    # Remove spaces and convert to uppercase
    clean_text = "".join([c for c in text.upper() if c.isalpha()])

    # Pad with 'X' if length is odd
    if len(clean_text) % 2 != 0:
        clean_text += "X"

    vectors = []
    for i in range(0, len(clean_text), 2):
        char1 = clean_text[i]
        char2 = clean_text[i + 1]
        # Convert A=0, B=1, ..., Z=25
        v = [ord(char1) - ord("A"), ord(char2) - ord("A")]
        vectors.append(v)

    return clean_text, vectors


def hill_encrypt(plaintext, key_matrix):
    clean_text, vectors = text_to_vectors(plaintext)
    K = np.array(key_matrix)

    ciphertext_nums = []
    for v in vectors:
        P = np.array(v).reshape(2, 1)
        # Matrix multiplication modulo 26
        C = np.dot(K, P) % 26
        ciphertext_nums.extend(C.flatten())

    # Convert numbers back to characters
    ciphertext = "".join([chr(num + ord("A")) for num in ciphertext_nums])
    return clean_text, ciphertext


def main():
    message = "We live in an insecure world"
    # Given key K = [[3, 3], [2, 7]]
    key = [[3, 3], [2, 7]]

    clean_text, ciphertext = hill_encrypt(message, key)

    print("=" * 50)
    print("           HILL CIPHER ENCRYPTION")
    print("=" * 50)
    print("Original Message:  ", message)
    print("Prepared Text:     ", clean_text)
    print("Ciphertext:        ", ciphertext)


if __name__ == "__main__":
    main()