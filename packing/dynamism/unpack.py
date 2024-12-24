from pwn import *

# Challenge retrieves function from server, then executes them.
# It retrieves first data and the xor (look at rsi register)
# Then prepares the input by xoring it with the xor
# Finally, compares the xored input with the data.
# To solve, just reverse the data with the xor and obtain the flag

data = [0x2648a0c1cd54abaa,
        0x3c46afcfde54b5ab,
        0x3178e2e5d05ba8a5,
        0x3c78b7d5cd6ab2a3,
        0x1740a2d6cc6aa2a4,
        0x265ea7e5c75ab5aa,
        0x3c4e9cc9cb4298ed,
        0x35189cded854af93]

xor = 0x4827c3baaa35c7cc

flag = ""
for i in range(len(data)):
    data[i] = data[i] ^ xor
    flag += p64(data[i]).decode()

print(flag)