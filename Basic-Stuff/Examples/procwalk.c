#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>


int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <process_name>\n", argv[ 0 ] );
        return 1;
    }

    LPCSTR processName = argv[ 1 ];

    // printf( "Searching for process: %s\n", processName );


    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError() );
        return 1;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    if ( !Process32First( hSnapshot, &pe32 ) ) {
        fprintf( stderr, "[-] Process32First failed. Error: %lu\n", GetLastError() );
        CloseHandle( hSnapshot );
        return 1;
    }

    DWORD foundCount = 0;

    do {
        if ( stricmp( pe32.szExeFile, processName ) == 0 ) {
            printf( "[+] PID=%-6lu PPID=%-6lu Threads=%-6lu %s\n", pe32.th32ProcessID, pe32.th32ParentProcessID, pe32.cntThreads, pe32.szExeFile );
            foundCount++;
        }
    } while ( Process32Next( hSnapshot, &pe32 ) );

    if ( foundCount == 0 ) {
        printf( "[-] No processes found with the name: %s\n", processName );
    }
    else {
        printf( "[+] Total processes found: %lu\n", foundCount );
    }

    CloseHandle( hSnapshot );
    return 0;
}