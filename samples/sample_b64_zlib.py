
# This file is safe. It contains encoded "Hello World" to test detectors.
import base64
import zlib

# "Hello World" -> b64 -> zlib -> b64
payload = "eJzLSM3JyVcozy/KSQEAGgsEXQ=="
# The above is zlib compressed "Hello World" then b64 encoded
decoded = zlib.decompress(base64.b64decode(payload))
print(decoded)
