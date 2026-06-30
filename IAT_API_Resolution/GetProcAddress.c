#include <windows.h>
#include <stdio.h>
#include <winternl.h>   

FARPROC MyGetProcAddress( HMODULE hModule, LPCSTR lpProcName ) {

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;
    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )hModule + pDosHeader->e_lfanew );
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;

    if ( !exportDirRVA ) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )hModule + exportDirRVA );
    PDWORD pAddressOfNames = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfNames );
    PDWORD pAddressOfFunctions = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfFunctions );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( BYTE* )hModule + pExportDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDir->NumberOfFunctions; i++ ) {
        LPCSTR functionaName = ( LPCSTR )( ( BYTE* )hModule + pAddressOfNames[ i ] );
        // printf( "[+] Function Name: %s\n", functionaName );
        if ( strcmp( functionaName, lpProcName ) == 0 ) {
            return ( FARPROC )( ( BYTE* )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );
        }
    }
    return NULL;
}

int main() {

    HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
    if ( !hKernel32 ) {
        fprintf( stderr, "[-] GetModuleHandleA failed with error: %lu\n", GetLastError() );
        return 1;
    }
    FARPROC pLoadLibraryA = MyGetProcAddress( hKernel32, "LoadLibraryA" );
    if ( pLoadLibraryA ) {
        printf( "[+] LoadLibraryA found at address: 0x%p\n", pLoadLibraryA );
    }
    else {
        printf( "[-] LoadLibraryA not found.\n" );
    }
    return 0;
}