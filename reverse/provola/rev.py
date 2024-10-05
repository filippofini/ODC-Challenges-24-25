from libdebug import debugger
import string

def provolino(t, bp):
    pass

d = debugger("./provola", continue_to_binary_entrypoint=False) #continue_to_binary_entrypoint=False


flag = b"$"*37
max_counter = 0

for i in range(37):
    for c in string.printable:
        new_flag = flag[:i] + c.encode() + flag[i+1:]
 
        r = d.run()

        bp = d.bp(0x1A0F, file="provola", callback=provolino) #hardware=True

        d.cont()

        r.recvuntil(b'password.')
        r.sendline(new_flag)

        d.wait()
        d.kill()

        if bp.hit_count > max_counter:
            max_counter = bp.hit_count
            flag = new_flag
            print(flag)
            break

        #print(c, bp.hit_count)