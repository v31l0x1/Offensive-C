import base64
import sys

KEY = "mysecretkey"

def xor(data, key):
    key = str(key)
    l = len(key)
    output = bytearray()

    for i in range(len(data)):
        current = data[i]  # Byte value (integer)
        current_key = key[i % len(key)]
        output.append(current ^ ord(current_key))  # XOR byte with key char

    return output.decode("latin1")  # Return as string for printCiphertext

def printCiphertext(ciphertext):
    print(
        "unsigned char payload[] = { 0x"
        + ", 0x".join(hex(ord(x))[2:] for x in ciphertext)
        + " };"
    )

def writeToFile(ciphertext, filename):
    with open(filename, "wb") as f:
        f.write(ciphertext.encode("latin1"))

if len(sys.argv) != 2:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as f:
        raw_payload = f.read()
except Exception as e:
    print("Error reading file: %s" % e)
    sys.exit(1)

ciphertext = xor(raw_payload, KEY)
printCiphertext(ciphertext)
# writeToFile(ciphertext, "payload.enc")