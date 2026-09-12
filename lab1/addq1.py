#BRUTE FORCE ATTACK ON ADDITIVE CIPHER
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

for key in range(26):

    plaintext = ""

    for char in ciphertext:
        if char.isalpha():
            num = ord(char) - ord('A')
            original_num = (num - key) % 26
            plaintext += chr(original_num + ord('A'))
        else:
            plaintext += char

    print("Key =", key, ":", plaintext)

"""
1. Use a brute-force attack to decipher the following message enciphered by Alice using an
additive cipher. Suppose that Alice always uses a key that is close to her birthday, which is on
the 13th of the month:
NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY
1. Eve secretly gets access to Alice's computer and using her cipher types "abcdefghi". The
screen shows "CABDEHFGL". If Eve knows that Alice is using a keyed transposition cipher,
answer the following questions:
a. What type of attack is Eve launching?
b. What is the size of the permutation key?

Also, you don't need to literally put "Alice" or "Eve" in the code. Those are the roles in the question:
Alice = the person who encrypts
Eve = the attacker
Ciphertext = encrypted message Eve sees
Plaintext = original message Eve is trying to recover

Here Eve is represented by the program. Alice is the hypothetical sender whose ciphertext we have.

"""

#since alice's bday is on 13th we can make eve smarter by first checking keys around 13
#keys = [13, 12, 14, 11, 15, 10, 16, 9, 17, 8, 18, 7, 19, 6, 20, 5, 21, 4, 22, 3, 23, 2, 24, 1, 25, 0]
#for k in keys: ...