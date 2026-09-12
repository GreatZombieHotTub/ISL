plaintext = "Life is full of surprises"
key = "HEALTH"

ciphertext = ""
key_index = 0

for char in plaintext:

    if char.isalpha():

        p = ord(char.upper()) - ord('A')
        k = ord(key[key_index % len(key)].upper()) - ord('A')

        c = (p + k) % 26

        ciphertext += chr(c + ord('A'))

        key_index += 1

    else:
        ciphertext += char

print("Plaintext :", plaintext)
print("Key       :", key)
print("Ciphertext:", ciphertext)