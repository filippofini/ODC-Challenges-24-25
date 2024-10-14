import angr
import claripy

flag_len = 23

project = angr.Project("./cracksymb")

input_flag = claripy.BVS('flag', 8 * flag_len)

state = project.factory.entry_state(stdin=input_flag, add_options={angr.options.LAZY_SOLVES})

for byte in input_flag.chop(8):
	state.add_constraints(byte >= 0x20)
	state.add_constraints(byte < 0x7f)
	
state.add_constraints(input_flag.chop(8)[0] == ord('f'))
state.add_constraints(input_flag.chop(8)[1] == ord('l'))
state.add_constraints(input_flag.chop(8)[2] == ord('a'))
state.add_constraints(input_flag.chop(8)[3] == ord('g'))
state.add_constraints(input_flag.chop(8)[4] == ord('{'))
state.add_constraints(input_flag.chop(8)[flag_len-1] == ord('}'))

simgr = project.factory.simulation_manager(state)

simgr.explore(find=0x4033BB , avoid=0x4033C9)

if simgr.found:
	s = simgr.found[0].solver

	flag = s.eval(input_flag)
	flag = bytes.fromhex(hex(flag)[2:]).decode('utf-8')

	print(flag)
else:
	print('unsat')