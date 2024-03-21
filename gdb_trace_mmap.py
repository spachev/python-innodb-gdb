import sys

def die(msg):
    sys.write(sys.stderr, "Fatal:" + msg)
    gdb.execute("quit")

def on_exit(ev):
    gdb.execute("quit")

n_hits = 0
if 'max_hits' not in globals():
    max_hits = 10 # invoke with --ex "py max_hits=value" to change

if 'funcs' not in globals():
    funcs = 'mmap,brk'

class MemoryBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super(MemoryBreakpoint, self).__init__(spec, gdb.BP_BREAKPOINT, internal = False)

    def stop(self):
        gdb.execute("bt")
        global n_hits
        n_hits += 1
        print("n_hits={}".format(n_hits))
        if n_hits >= max_hits:
            gdb.execute("quit")
        #safe_cont()
        return False

def safe_cont():
    gdb.execute("info threads")
    for i in range(1,100):
        try:
            gdb.execute("c")
            return
        except:
            print("Got error: try {}".format(i))

gdb.execute("set pagination 0")
gdb.execute("set confirm off")
func_list = funcs.split(",")
bp_list = []

for f in func_list:
    bp_list.append(MemoryBreakpoint(f))
procs = gdb.inferiors()
if len(procs) < 1:
    die("No process loaded or attached")
inf_proc = procs[0]

if not inf_proc.was_attached:
    gdb.execute("run")
else:
    gdb.execute("c")

