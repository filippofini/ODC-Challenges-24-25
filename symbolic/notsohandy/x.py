import angr
import claripy


binary_path = 'notsohandy'

project = angr.Project(binary_path, auto_load_libs=False)
flag_len = 49
base = 0x400000
find = 0x1422+base
avoid = [0x12A5+base, 0x13DC+base, 0x1433+base]

input_flag = claripy.BVS('flag', 8 * flag_len)
state = project.factory.entry_state(args=[binary_path, input_flag], add_options={angr.options.LAZY_SOLVES})

for byte in input_flag.chop(8):
    state.add_constraints(byte >= 0x20)
    state.add_constraints(byte < 0x7f)
    
simulation = project.factory.simulation_manager(state)
simulation.explore(find=find , avoid=avoid)

if simulation.found:
    solution_state = simulation.found[0]
    solution = solution_state.solver.eval(input_flag, cast_to=bytes)
    print("Correct flag: ", solution)
else:
    print('NO solution\n')