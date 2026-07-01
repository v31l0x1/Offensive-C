#include "Defines.h"

DWORD findPID( LPCSTR procName ) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        printf( "CreateToolhelp32Snapshot failed: %d\n", GetLastError() );
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    DWORD pid = 0;

    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            if ( _strcmpi( pe32.szExeFile, procName ) == 0 ) {
                pid = pe32.th32ProcessID;
                break;
            }

        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

    CloseHandle( hSnapshot );
    return pid;
}

DWORD findPIDByEnum( LPCSTR procName ) {
    DWORD pid[ 1024 ], cb = 0;

    if ( !EnumProcesses( pid, sizeof( pid ), &cb ) ) {
        printf( "EnumProcesses failed: %d\n", GetLastError() );
        return 0;
    }

    DWORD procCount = cb / sizeof( DWORD );

    for ( DWORD i = 0; i < procCount; i++ ) {
        HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid[ i ] );

        if ( !hProcess )  continue;

        char Name[ MAX_PATH ] = { 0 };

        if ( GetModuleBaseNameA( hProcess, NULL, Name, MAX_PATH ) ) {
            if ( _strcmpi( Name, procName ) == 0 ) {
                CloseHandle( hProcess );
                return pid[ i ];
            }
        }
        CloseHandle( hProcess );
    }

    return 0;
}

DWORD findPIDByNtQuery( LPCWSTR procName ) {

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

    if ( !hNtdll ) {
        printf( "GetModuleHandleA failed: %d\n", GetLastError() );
        return 0;
    }

    fnNtQuerySystemInformation NtQuerySystemInformation = ( fnNtQuerySystemInformation )GetProcAddress( hNtdll, "NtQuerySystemInformation" );

    if ( !NtQuerySystemInformation ) {
        printf( "GetProcAddress failed: %d\n", GetLastError() );
        return 0;
    }

    NTSTATUS status;
    ULONG returnLength = 0;
    status = NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &returnLength );

    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        printf( "[-] ~ NtQuerySystemInformation call failed: 0x%X\n", status );
        return 0;
    }

    PVOID buffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, returnLength );
    if ( !buffer ) {
        printf( "[-] HeapAlloc failed: %d\n", GetLastError() );
        return 0;
    }

    status = NtQuerySystemInformation( SystemProcessInformation, buffer, returnLength, &returnLength );

    if ( !NT_SUCCESS( status ) ) {
        printf( "[-] NtQuerySystemInformation failed: 0x%X\n", status );
        HeapFree( GetProcessHeap(), 0, buffer );
        return 0;
    }

    DWORD pid = 0;
    PSYSTEM_PROCESS_INFORMATION pInfo = ( PSYSTEM_PROCESS_INFORMATION )buffer;
    while ( TRUE ) {
        if ( pInfo->ImageName.Buffer ) {
            PWCHAR fileName = wcsrchr( pInfo->ImageName.Buffer, L'\\' );
            if ( fileName ) {
                fileName++;
            }
            else {
                fileName = pInfo->ImageName.Buffer;
            }

            if ( _wcsicmp( fileName, procName ) == 0 ) {
                pid = ( DWORD )( ULONG_PTR )pInfo->UniqueProcessId;
                break;
            }

        }

        if ( pInfo->NextEntryOffset == 0 ) {
            break;
        }

        pInfo = ( PSYSTEM_PROCESS_INFORMATION )( ( PBYTE )pInfo + pInfo->NextEntryOffset );

    }

    HeapFree( GetProcessHeap(), 0, buffer );
    return pid;
}


int main( void ) {

    LPCSTR procName = "notepad.exe";
    DWORD pid = findPID( procName );
    if ( pid ) {
        printf( "[+] Found %s with PID: %d (CreateToolhelp32Snapshot)\n", procName, pid );
    }
    else {
        printf( "[-] %s not found\n", procName );
    }

    pid = findPIDByEnum( procName );
    if ( pid ) {
        printf( "[+] Found %s with PID: %d (EnumProcesses)\n", procName, pid );
    }
    else {
        printf( "[-] %s not found\n", procName );
    }

    LPCWSTR wProcName = L"notepad.exe";
    pid = findPIDByNtQuery( wProcName );
    if ( pid ) {
        wprintf( L"[+] Found %ls with PID: %ld (NtQuerySystemInformation)\n", wProcName, pid );
    }
    else {
        wprintf( L"[-] %ls not found\n", wProcName );
    }

    return 0;

}

