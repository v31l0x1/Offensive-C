#include <stdio.h>
#include <string.h>

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void xor_buffer(unsigned char* buf, size_t len, const unsigned char* key, size_t key_len) {
    int j = 0;
    for (int i = 0; i < len; i++) {
        if (j == key_len - 1 ) j = 0;
        buf[i] ^= key[j++];
        j++;
    }
}

int main( int argc, char* argv[] ) {

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <string> <key_hex>\n", argv[0]);
        return 1;
    }

    unsigned char key[256];    
    size_t key_len = 0;

    memcpy(key, argv[2], strlen(argv[2]));
    key_len = strlen(argv[2]);


    size_t len = strlen(argv[1]);
    unsigned char buf[256];
    if (len > sizeof(buf)) {
        fprintf(stderr, "[!] input too long\n");
        return 1;
    }

    memcpy(buf, argv[1], len);

    print_hex("[+] Plaintext: ", buf, len);

    xor_buffer(buf, len, key, strlen(key));

    print_hex("[+] Encoded: ", buf, len);

    xor_buffer(buf, len, key, strlen(key));
    buf[len] = '\0';
    print_hex("[+] Decoded (hex): ", buf, len);
    printf("[+] Decoded String: %s\n", buf);

    return 0;
}   