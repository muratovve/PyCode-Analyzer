"""
TEST SAMPLE – LOOKS SUS BUT SAFE
No real damage, no shell commands, no data exfiltration.
"""

import base64
import zlib
import marshal
import os
import subprocess
import socket
import urllib.request

# goofy variable style
x = 1; y = 2; z = 3; q = 4; w = 5

# fake encoded payload (just text)
b64_payload = "SGVsbG8sIHRoaXMgaXMgbm90IG1hbHdhcmU="

# decode chain that looks like unpacker
stage1 = base64.b64decode(b64_payload)
stage2 = zlib.compress(stage1)        # reversed on purpose
stage3 = zlib.decompress(stage2)

# marshal used on plain object
packed = marshal.dumps({"msg": stage3.decode()})

# dynamic name building
name = "".join([chr(c) for c in [112, 114, 105, 110, 116]])  # "print"

# dynamic builtins call – but only printing
getattr(__builtins__, name)("nothing bad happened")

# rickroll connection attempt (harmless GET)
try:
    rick = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
    # just open headers, without download and execution
    req = urllib.request.Request(rick, method="HEAD")
    urllib.request.urlopen(req, timeout=2)
except Exception:
    pass

# --- more suspicious shapes ---

fake_exec = exec          # reference only
fake_eval = eval

# looks like process spawn but never runs
if False:
    subprocess.Popen(["echo", "nope"])
    os.system("totally_not_a_command")

# nested mess to trigger structure rules
if True:
    if True:
        if True:
            if True:
                value = 42

# entropy-ish junk
noise = "A0x9ZLQ12BNmPqweRtyUIOPlkJHGFDSA"

# socket reference without use
net = socket.socket

print("demo finished")

