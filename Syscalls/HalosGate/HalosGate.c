#include <windows.h>
#include <stdio.h>

DWORD GetSSN( HMODULE hModule, LPCSTR lpFunctionName ) {


    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;

    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid DOS header\n" );
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( PBYTE )hModule + pDosHeader->e_lfanew );

    if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid NT header\n" );
        return 0;
    }


    PIMAGE_EXPORT_DIRECTORY pExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( ( PBYTE )hModule + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    if ( pExportDirectory->NumberOfNames == 0 ) {
        fprintf( stderr, "[-] No exported functions\n" );
        return 0;
    }

    PDWORD pAddressOfNames = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNames );
    PDWORD pAddressOfFunctions = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfFunctions );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDirectory->NumberOfNames; i++ ) {
        LPCSTR pFunctionName = ( LPCSTR )( ( PBYTE )hModule + pAddressOfNames[ i ] );

        PBYTE pFunctionAddress = ( PBYTE )( ( PBYTE )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );

        printf( "[+] %s: 0x%p\n", pFunctionName, pFunctionAddress );

    }

    return 0;

}


int main( void ) {

    HMODULE hModule = LoadLibraryA( "ntdll.dll" );
    if ( hModule == NULL ) {
        fprintf( stderr, "[-] Failed to load ntdll.dll\n" );
        return 1;
    }

    DWORD SSN = GetSSN( hModule, "NtAllocateVirtualMemory" );
    if ( SSN == 0 ) {
        fprintf( stderr, "[-] Failed to get SSN.\n" );
        return 1;
    }

    printf( "[+] SSN: 0x%X\n", SSN );

}