import sys

def rc4(data, key):
    keylen = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % keylen]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    encrypted = bytearray()
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        encrypted.append(data[n] ^ s[(s[i] + s[j]) % 256])
    
    return encrypted


def writeToFile(filename, data):
    with open(filename, "wb") as f:
        f.write(data)
    print(f"Witten {filename}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./rc4.py <key> <input_file>")
        sys.exit(1)

    key = sys.argv[1]
    filename = sys.argv[2]

    with open(filename, "rb") as f:
        data = f.read()

    encrypted_data = rc4(data, key.encode())

    print("unsigned char payload[] = { " + ", ".join(f"0x{byte:02x}" for byte in encrypted_data) + " }")
    print(f"unsigned char key[] = \"{key}\";")
    # writeToFile(f"{filename}.enc", encrypted_data)