from pwn import *

part1 = 0x988a215bec73afb4
part2 = 0xef48e5cb65f245cf
check1 = 0xedba58208b12c3d2
check2 = 0x9c1791b3569c1abd
part3 = 0xa0e9997a1f26e55d
part4 = 0xf997be04d7255ecb
check3 = 0x8e9aa8252c50896d
check4 = 0x84e18d69e05c70e5


# XOR the hex to find the original flag
flag = p64(part1 ^ check1) + p64(part2 ^ check2) + p64(part3 ^ check3) + p64(part4 ^ check4)

print(flag.decode())

# Find the decode function
# Two rounds: first it prepares for the first part, then the second.
# insert random flag (1 char) and break at puts function.
# When puts is printing NANI, dump function decode that manages the first part
# dump memory decode 0x00005555555551b9 0x000055555555548e
# Use patch.py to get the unpacked code for the first part and analyze with ghidra
# see that a xor between values and flag is performed, and then checked
# extract the first part (reverse xor)
# Rerun the code and do the same as before but insert first half of the flag found
# Now the decode function has checked the first part and prepared for the second
# dump memory decode2 0x00005555555551b9 0x000055555555548e
# Use patch.py to get the unpacked code for the second part and analyze with ghidra
# Extarct the new data 
# Done