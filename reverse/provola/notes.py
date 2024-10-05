from libdebug import debugger

def provolino(t, bp):
    print(t.regs.rax) #rax register of the breakpoint hit by the thread

def force_fail(t, hs):
    t.syscall_number = 0
    t.syscall_arg0 = 0
    t.syscall_arg1 = 0
    t.syscall_arg2 = 0
    t.syscall_arg3 = 0

def modify_ret_value(t, hs):
    t.rex.rax = 0x10

d = debugger("./provola", continue_to_binary_entrypoint=False) #optional parameters after ,

d.run()

bp = d.bp(0x1AC3, file="provola", callback=provolino) #when program hits the breakpoint, it continues executing the function callback

hs = d.handle_syscall("read", on_enter=force_fail, on_exit=modify_ret_value)

cs = d.catch_signal(11, callback=provolino)

d.hijack_signal()
d.hijack_syscall("read", "write")

d.cont()

d.threads[0].regs.rax

d.wait()

"""
if bp.hit_on(d):
    print(d.regs.rax)
    d.cont()

if hs.hit_on_enter(d):
    print(d.regs.rax)
    d.cont()

if hs.hit_on_exit(d):
    print(d.regs.rax)
    d.cont()
"""

d.wait()
d.kill()