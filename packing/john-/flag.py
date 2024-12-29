# Last real check, last part of flag
bytes = [0x0B, 0x4C, 0x0F, 0, 1, 0x16, 0x10, 7, 9, 0x38, 0x00]

def decode(flag, i):
    if (i + 22 >= 33):
        return 1
    if bytes[i] ^ ord(flag[i + 20]) == ord(flag[i + 21]):
        return decode(flag, i + 1)
    return 0

flag = list("flag{packer-4_3-1337&-") + [' '] * 10 + ['}']
for i in range(11):
    flag[i+21] = chr(ord(flag[i+20]) ^ bytes[i])
str_flag = "".join(flag)
print(decode(str_flag, 0))


print(len(flag))
print("".join(flag))