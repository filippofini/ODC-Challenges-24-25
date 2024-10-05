from libdebug import debugger
import string

def provolino(t, bp):
    pass

def skip_sleep(t, hs):
    t.syscall_number = 0
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

d = debugger("./slow_provola", continue_to_binary_entrypoint=False) #continue_to_binary_entrypoint=False


flag = b"$" * 68

stop = 0x1A5E
increment = 0xA8

for i in range(68):
    for c in string.printable:
        new_flag = flag[:i] + c.encode() + flag[i+1:]

        r = d.run()
        
        bp = d.bp(stop, file="slow_provola", callback=provolino) #hardware=True
        hs = d.handle_syscall("clock_nanosleep", on_enter=skip_sleep)

        d.cont()

        r.recvuntil(b'password.')
        r.sendline(new_flag)

        d.wait()
        d.kill()

        if bp.hit_count == 32:
            if i < 50:
                stop += increment
            elif i == 50:
                stop = 0x3BCD
            elif i == 51:
                stop = 0x3C66
            else:
                stop += 153
            
            flag = new_flag
            print(flag)
            break
        #print(c, bp.hit_count)