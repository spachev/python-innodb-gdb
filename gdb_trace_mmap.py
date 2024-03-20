import sys

def die(msg):
    sys.write(sys.stderr, "Fatal:" + msg)
    gdb.execute("quit")

def on_exit(ev):
    gdb.execute("quit")

n_hits = 0
if 'max_hits' not in globals():
    max_hits = 10 # invoke with --ex "py max_hits=value" to change
class MmapBreakpoint(gdb.Breakpoint):
    def __init__(self, spec):
        super(MmapBreakpoint, self).__init__(spec, gdb.BP_BREAKPOINT, internal = False)

    def stop(self):
        gdb.execute("bt")
        global n_hits
        n_hits += 1
        print("n_hits={}".format(n_hits))
        if n_hits >= max_hits:
            gdb.execute("quit")
        return False

gdb.execute("set pagination 0")
b = MmapBreakpoint("mmap")
procs = gdb.inferiors()
if len(procs) < 1:
    die("No process loaded or attached")
inf_proc = procs[0]

if not inf_proc.was_attached:
    gdb.execute("run")
else:
    gdb.execute("c")
