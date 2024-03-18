import angr
import sys

path = './a.out'


def win(state):
	if b'Good' in state.posix.dumps(sys.stdout.fileno()):
		return True
	return False


def lose(state):
	if b'False' in state.posix.dumps(sys.stdout.fileno()):
		return True
	return False


project  =  angr.Project(path , auto_load_libs = False , main_opts={'base_addr':0})
state = project.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
simg = project.factory.simgr(state)
simg.explore(find=win , avoid = lose)


if simg.found:
	sol_state = simg.found[0]
	print(sol_state.posix.dumps(sys.stdin.fileno()))
