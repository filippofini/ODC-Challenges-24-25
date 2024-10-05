magic0_values = [
    0x1b, 0x51, 0x17, 0x2a, 0x1e, 0x4e, 0x3d, 0x10, 0x17, 0x46, 0x49, 0x14, 0x3d
]

magic1_values = [
    0xeb, 0x51, 0xb0, 0x13, 0x85, 0xb9, 0x1c, 0x87, 0xb8, 0x26, 0x8d, 0x07
]

# Part 1: Generate the flag using magic0_values and "babbuz"
flag = ""

for i in range(13):
    # XOR the integer value from magic0_values with the ASCII value of the corresponding character from "babbuz"
    xor_result = ord("babbuz"[i % 6]) ^ magic0_values[i]
    
    # Convert the XOR result back to a character and append to flag
    flag += chr(xor_result)

print("Flag:", flag)  # Output flag
print("Flag Length:", len(flag))  # Output flag length

# Part 2: Reverse engineer key1 from magic1_values
key2 = -69
flag2 = ""

# Reverse engineer key1 based on the magic1 values
for i in range(12):
    # Find the difference between magic1 and the current key2 value
    key_value = chr(magic1_values[i] - key2)
    
    # Add the key_value to key1 (in reverse, we are trying to find key1 values)
    flag2 += key_value
    print(flag2)
    
    # Update key2 for the next iteration (reverse of adding *key1)
    key2 -= ord(key_value)

# Convert the key1 values to characters and merge with the flag
final_output = flag + flag2

print("Flag 2:", flag2)  # Output the recovered key1 as string
print("Final Output (Flag + Recovered Key):", final_output)  # Concatenate flag and key1