# Angr doesn't work from a certain point, don't know why

import angr
import claripy

flag_len = 33

BASE_ADDRESS = 0x08048000

binary_path = "./john_unpacked9"

project = angr.Project(binary_path)

input_flag = claripy.BVS('flag', 8 * flag_len)


state = project.factory.entry_state(args=[binary_path, input_flag])

# First part of flag obtain looking directly at GDB
print(len("flag{packer-4_3-1337&-j-WXXYO_XQh}"))
print("flag{packer-4_3-1337&-}")

for byte in input_flag.chop(8):
	state.add_constraints(byte >= 0x20)
	state.add_constraints(byte < 0x7f)


state.add_constraints(input_flag.chop(8)[0] == ord('f'))
state.add_constraints(input_flag.chop(8)[1] == ord('l'))
state.add_constraints(input_flag.chop(8)[2] == ord('a'))
state.add_constraints(input_flag.chop(8)[3] == ord('g'))
state.add_constraints(input_flag.chop(8)[4] == ord('{'))

state.add_constraints(input_flag.chop(8)[5] == ord('p'))
state.add_constraints(input_flag.chop(8)[6] == ord('a'))
state.add_constraints(input_flag.chop(8)[7] == ord('c'))
state.add_constraints(input_flag.chop(8)[8] == ord('k'))
state.add_constraints(input_flag.chop(8)[9] == ord('e'))
state.add_constraints(input_flag.chop(8)[10] == ord('r'))

state.add_constraints(input_flag.chop(8)[11] == ord('-'))
state.add_constraints(input_flag.chop(8)[12] == ord('4'))
state.add_constraints(input_flag.chop(8)[13] == ord('_'))
state.add_constraints(input_flag.chop(8)[14] == ord('3'))
state.add_constraints(input_flag.chop(8)[15] == ord('-'))
state.add_constraints(input_flag.chop(8)[16] == ord('1'))
state.add_constraints(input_flag.chop(8)[17] == ord('3'))
state.add_constraints(input_flag.chop(8)[18] == ord('3'))
state.add_constraints(input_flag.chop(8)[19] == ord('7'))
state.add_constraints(input_flag.chop(8)[20] == ord('&'))
state.add_constraints(input_flag.chop(8)[21] == ord('-'))
state.add_constraints(input_flag.chop(8)[flag_len-1] == ord('}'))


simulation = project.factory.simulation_manager(state)

simulation.explore(find=0x080497C2)

if simulation.found:
    print(f"FOUND!!!\n")
    solution_state = simulation.found[0]
    solution = solution_state.solver.eval(input_flag, cast_to=bytes)
    print("Correct flag: ", solution.decode())
else:
    print('NO solution\n')