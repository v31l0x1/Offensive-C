#include <windows.h>
#include <stdio.h>


void printHexDump( const BYTE* buffer, size_t length, char* line, size_t lineSize ) {

    size_t pos = 0;
    for ( size_t i = 0; i < 16; ++i ) {
        if ( i < length ) {
            int n = _snprintf_s( line + pos, lineSize - pos, _TRUNCATE, "%02X ", buffer[i] );
            if ( n > 0 )
                pos += ( size_t )n;
        }
        else {
            int n = _snprintf_s( line + pos, lineSize - pos, _TRUNCATE, "   " );
            if ( n > 0 )
                pos += ( size_t )n;
        }
    }

    if ( pos + 1 < lineSize ) {
        line[pos++] = '|';
        for ( size_t i = 0; i < length && pos + 1 < lineSize; i++ ) {
            line[pos++] = ( buffer[i] >= 0x20 && buffer[i] <= 0x7E ) ? ( char )buffer[i] : '.';
        }
        if ( pos < lineSize ) line[pos++] = 0;
    }

}

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s filepath\n", argv[0] );
        return -1;
    }

    char* filePath = argv[1];
    printf( "[+] File Path: %s\n", filePath );

    HANDLE hFile = CreateFileA( filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

    if ( hFile == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] Failed to open file: %lu\n", GetLastError() );
        return -1;
    }

    DWORD fileSize = GetFileSize( hFile, NULL );

    BYTE buffer[16] = { 0 };
    DWORD bytesToRead = 16;
    DWORD bytesRead = 0;
    size_t offset = 0;
    char line[128];

    while ( ReadFile( hFile, buffer, bytesToRead, &bytesRead, NULL ) && bytesRead > 0 ) {
        printHexDump( buffer, bytesRead, line, sizeof( line ) );
        printf( "%08zX: %s\n", offset, line );
        offset += bytesRead;
        if ( offset >= fileSize ) break;
    }
    printf( "[+] Read %lu bytes from file\n", fileSize );


    return 0;
}