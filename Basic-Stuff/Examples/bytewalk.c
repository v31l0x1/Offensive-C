#include <stdio.h>
#include <windows.h>



int main( int argc, char* argv[] ) {

    DWORD value = 0x12345678;

    if ( argc < 2 ) {
        value = ( DWORD )strtoul( argv[ 1 ], NULL, 0 );
    }

    BYTE* bytePtr = ( BYTE* )&value;
    printf( "Value: 0x%08X\n", value );
    printf( "Address: %p\n", ( void* )bytePtr );
    for ( size_t i = 0; i < sizeof( DWORD ); i++ ) {
        printf( "Byte %zu @ %p: 0x%02X\n", i, ( void* )( bytePtr + i ), bytePtr[ i ] );
    }

    BYTE raw[ 4 ] = { 0 };
    memcpy( raw, &value, sizeof( DWORD ) );

    DWORD recovered = ( ( DWORD )raw[ 0 ] ) | ( ( DWORD )raw[ 1 ] << 8 ) | ( ( DWORD )raw[ 2 ] << 16 ) | ( ( DWORD )raw[ 3 ] << 24 );
    printf( "\n[+] Recovered Value: 0x%08X %s\n", recovered, recovered == value ? "OK" : "Mismatch" );

    return 0;
}