#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <Windows.h>

int main( void ) {
    printf( "\n=== C integer types ===\n" );
    printf( " char      : %zu bytes range %d to %d\n", sizeof( char ), SCHAR_MIN, SCHAR_MAX );
    printf( " short     : %zu bytes range %d to %d\n", sizeof( short ), SHRT_MIN, SHRT_MAX );
    printf( " int       : %zu bytes range %d to %d\n", sizeof( int ), INT_MIN, INT_MAX );
    printf( " long      : %zu bytes range %ld to %ld\n", sizeof( long ), LONG_MIN, LONG_MAX );
    printf( " long long : %zu bytes range %lld to %lld\n", sizeof( long long ), LLONG_MIN, LLONG_MAX );

    printf( "\n=== C fixed-width integer types ===\n" );
    printf( " uint8_t   : %zu bytes range %d to %d\n", sizeof( uint8_t ), 0, UINT8_MAX );
    printf( " uint16_t  : %zu bytes range %d to 0x%04X\n", sizeof( uint16_t ), 0, UINT16_MAX );
    printf( " uint32_t  : %zu bytes range %d to 0x%08X\n", sizeof( uint32_t ), 0, UINT32_MAX );
    printf( " uint64_t  : %zu bytes range %d to 0x%016llX\n", sizeof( uint64_t ), 0, UINT64_MAX );


    printf( "\n=== C Windows typedefs ===\n" );
    printf( " BYTE      : %zu bytes\n", sizeof( BYTE ) );
    printf( " WORD      : %zu bytes\n", sizeof( WORD ) );
    printf( " DWORD     : %zu bytes\n", sizeof( DWORD ) );
    printf( " QWORD     : %zu bytes\n", sizeof( unsigned __int64 ) );
    printf( " BOOL      : %zu bytes\n", sizeof( BOOL ) );
    printf( " HANDLE    : %zu bytes\n", sizeof( HANDLE ) );
    printf( " HMODULE   : %zu bytes\n", sizeof( HANDLE ) );
    printf( " LPVOID    : %zu bytes\n", sizeof( LPVOID ) );
    printf( " SIZE_T    : %zu bytes\n", sizeof( SIZE_T ) );


    printf( "\n=== Pointer Size ===\n" );
    printf( " void *    : %zu bytes (arch: %s)\n", sizeof( void* ), sizeof( void* ) == 8 ? "x64" : "x86" );

    return 0;
}