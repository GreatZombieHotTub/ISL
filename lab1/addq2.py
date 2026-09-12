#Known-plaintext attack on keyed transposition cipher
plaintext = "abcdefghi"
ciphertext = "cabdehfgi"

permutation = []

for char in ciphertext:
    position = plaintext.index(char)
    permutation.append(position + 1)

print("Plaintext :", plaintext)
print("Ciphertext:", ciphertext)
print("Permutation Key:", permutation)
print("Key Size:", len(permutation))

"""
Plaintext:  A B C D E F G H I
            ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓ ↓
Key:        3 1 2 4 5 8 6 7 9

Ciphertext: C A B D E H F G I

"""