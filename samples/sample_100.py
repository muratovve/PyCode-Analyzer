# detector_high_risk_test.py
# Safe payload: prints a line, but wrapped in all the usual obfuscation-ish patterns.

import base64 as b
import zlib as z
import marshal
import importlib
import subprocess
import os
import sys
import socket

# single-char vars spam (to trigger density heuristic)
a = 1; c = 2; d = 3; e = 4; f = 5; g = 6; h = 7; i = 8; j = 9; k = 10; l = 11; m = 12

# hex blob + marker strings (static regex / marker checks)
hex_blob = "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c"
zlib_marker = "x\\x9c"   # yes, literally this substring
bz2_marker = "BZh"

# build "exec" name via chr + join (heuristic flags)
name_exec = "".join([chr(x) for x in [101, 120, 101, 99]])  # 'exec'

# payload that is harmless but goes through pack/unpack chain
payload_src = "print('detector tripwire: safe payload executed')"

# compile -> marshal -> zlib -> base64
co = compile(payload_src, "<tripwire>", "exec")  # should flag compile()
blob = marshal.dumps(co)
packed = z.compress(blob)
b64 = b.b64encode(packed).decode("ascii")

# base64 -> zlib -> marshal -> exec (pipeline pattern)
data = b.b64decode(b64)
raw = z.decompress(data)
co2 = marshal.loads(raw)

# dynamic exec via getattr(__builtins__, 'exec')
getattr(__builtins__, name_exec)(co2)

# extra “classic” risky calls (won't run, but AST should still see them)
if False:
    eval("1+1")  # eval usage
    __import__("os")  # __import__ usage
    subprocess.Popen(["echo", "hi"])  # subprocess creation
    os.system("echo hi")  # os command execution

# deep nesting to push AST depth over your threshold
def deep():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        if True:
                            if True:
                                if True:
                                    if True:
                                        if True:
                                            if True:
                                                if True:
                                                    if True:
                                                        if True:
                                                            if True:
                                                                if True:
                                                                    return 123

deep()
