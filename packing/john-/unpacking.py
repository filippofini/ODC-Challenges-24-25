"""
from pwn import xor

# Take the content of the xor directly from binary
f = open('./john', 'rb')
content = f.read()

base = 0x8048000

# Key is given from the pointer to data + offset of 1, 2, 3, 4, 5
# everyone is 4 bytes (change to dword using 'd' on ida)
keys = [b'\x04\x03\x02\x01', b'\x40\x30\x20\x10', b'B00B', b'DEAD', b'\xff\xff\xff\xff']

# Unpack the binary 
def unpack(address, size, key):

    unpacked = b''
    offset = address - base
    for i in range(size*4, 4):
        unpacked += xor(content[offset+i:offset+i+4], key)
    
    return unpacked

address = 0x0804A020
key = keys[address % 5]
unpacked = unpack(address, 83, key)

# Insert unpacked code in old packed one
with open('john_unpacked', 'wb') as f:
    new_content = content[:address - base] + unpacked + content[address - base + len(unpacked)]
    f.write(new_content)

f.close()
"""


# Or we do manually by putting a breakpoint in 0x0804970E and dumping memory
# Or use libdebug


from libdebug import debugger

# Get from stack pointer to memory and size
def unpack(t, b):
    global content
    address = int.from_bytes(t.memory[t.regs.esp, 4], "little")
    size = int.from_bytes(t.memory[t.regs.esp, 4], "little")
    new_content = t.memory[address, size*4, "absolute"]
    offset = address - base
    content = content[:offset] + new_content + content[offset+size*4:]


with open('./john', 'rb') as f:
    content = f.read()


d = debugger(["./john", "flag{provola}"])

d.run()

base = d.maps.filter("binary")[0].base

# Put a breakpoint and read pointer and size
d.bp(0x08049295, hardware=True, callback=unpack, file="absolute")

d.cont()

d.wait()

d.kill()

with open('john_unpacked', 'wb') as f:
    f.write(content)