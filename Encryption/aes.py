import hashlib
import sys
from os import urandom

from Crypto.Cipher import AES

KEY = urandom(16)


def pad(s):
    pad_len = AES.block_size - len(s) % AES.block_size
    return s + bytes([pad_len] * pad_len)

def aesenc(plaintext_bytes, key):
    k = hashlib.sha256(key).digest()
    iv = bytes(16)
    plaintext_padded = pad(plaintext_bytes)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext_padded)

def write_bytes_to_file(filename, data):
    with open(filename, "wb") as f:
        f.write(data)

if len(sys.argv) != 2:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit(1)

try:
    with open(sys.argv[1], "rb") as f:
        raw_payload = f.read()
except Exception as e:
    print("Error reading file: %s" % e)
    sys.exit(1)

ciphertext = aesenc(raw_payload, KEY)
print("unsigned char payload[] = { " + ", ".join("0x{:02x}".format(b) for b in ciphertext) + " };")
print("unsigned char key[] = { " + ", ".join("0x{:02x}".format(b) for b in KEY) + " };")
# write_bytes_to_file("ciphertext.bin", ciphertext)
# write_bytes_to_file("key.bin", KEY)