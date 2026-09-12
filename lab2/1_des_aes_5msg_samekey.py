from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
import time
import matplotlib.pyplot as plt

messages = [
    "Hello World",
    "Secure Communication",
    "Cryptography Lab",
    "Information Security",
    "Encryption Testing"
]

# Keys
des_key = b"A1B2C3D4"

aes128_key = b"0123456789ABCDEF"

aes192_key = b"0123456789ABCDEF01234567"

aes256_key = b"0123456789ABCDEF0123456789ABCDEF"

iv_des = b"12345678"
iv_aes = b"1234567890123456"

# Store execution times
times = {
    "DES": [],
    "AES-128": [],
    "AES-192": [],
    "AES-256": []
}

# DES
for message in messages:
    data = pad(message.encode(), DES.block_size)

    start = time.perf_counter()

    cipher = DES.new(des_key, DES.MODE_CBC, iv_des)
    encrypted = cipher.encrypt(data)

    end = time.perf_counter()

    times["DES"].append(end - start)


# AES-128
for message in messages:
    data = pad(message.encode(), AES.block_size)

    start = time.perf_counter()

    cipher = AES.new(aes128_key, AES.MODE_CBC, iv_aes)
    encrypted = cipher.encrypt(data)

    end = time.perf_counter()

    times["AES-128"].append(end - start)


# AES-192
for message in messages:
    data = pad(message.encode(), AES.block_size)

    start = time.perf_counter()

    cipher = AES.new(aes192_key, AES.MODE_CBC, iv_aes)
    encrypted = cipher.encrypt(data)

    end = time.perf_counter()

    times["AES-192"].append(end - start)


# AES-256
for message in messages:
    data = pad(message.encode(), AES.block_size)

    start = time.perf_counter()

    cipher = AES.new(aes256_key, AES.MODE_CBC, iv_aes)
    encrypted = cipher.encrypt(data)

    end = time.perf_counter()

    times["AES-256"].append(end - start)


# Print execution times
for algorithm in times:
    print(algorithm)
    for i in range(5):
        print("Message", i + 1, ":", times[algorithm][i])
    print()


# Plot graph
x = range(1, 6)

plt.plot(x, times["DES"], marker="o", label="DES")
plt.plot(x, times["AES-128"], marker="o", label="AES-128")
plt.plot(x, times["AES-192"], marker="o", label="AES-192")
plt.plot(x, times["AES-256"], marker="o", label="AES-256")

plt.xlabel("Message Number")
plt.ylabel("Execution Time (seconds)")
plt.title("Execution Time of DES and AES")
plt.xticks(x)
plt.legend()
plt.show()

#its kind of a dataset where we can compare how each technique works on a msg, here 5 different msgs so we can plot the graph