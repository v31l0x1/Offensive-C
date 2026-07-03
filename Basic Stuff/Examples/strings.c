#include <stdio.h>
#include <windows.h>

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s filepath\n", argv[ 0 ] );
        return -1;
    }

    char* filePath = argv[ 1 ];
    printf( "[+] File Path: %s\n", filePath );

    HANDLE hFile = CreateFileA( filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );

    if ( hFile == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] Failed to open file: %lu\n", GetLastError() );
        return -1;
    }

    DWORD fileSize = GetFileSize( hFile, NULL );
    printf( "[+] File Size: %lu bytes\n", fileSize );

    BYTE buffer[ 16 ] = { 0 };
    DWORD bytesRead = 0;
    DWORD offset = 0;
    DWORD bytesToRead = 16;

    char ansiString[ 1024 ] = { 0 };
    size_t ansiPos = 0;

    wchar_t wideString1[ 512 ] = { 0 };
    size_t widePos1 = 0;

    wchar_t wideString2[ 512 ] = { 0 };
    size_t widePos2 = 0;

    while ( ReadFile( hFile, buffer, bytesToRead, &bytesRead, NULL ) && bytesRead > 0 ) {
        for ( DWORD i = 0; i < bytesRead; i++ ) {
            if ( buffer[ i ] >= 0x20 && buffer[ i ] <= 0x7E ) {
                if ( ansiPos < sizeof( ansiString ) - 1 ) {
                    ansiString[ ansiPos++ ] = ( char )buffer[ i ];
                }
            }
            else {
                if ( ansiPos >= 4 ) {
                    ansiString[ ansiPos ] = '\0';
                    printf( "%s\n", ansiString );
                }
                ansiPos = 0;
            }


            if ( ( offset + i ) % 2 == 0 ) {
                if ( i + 1 < bytesRead ) {
                    wchar_t wideChar = buffer[ i ] | ( buffer[ i + 1 ] << 8 );

                    if ( wideChar >= 0x20 && wideChar <= 0x7E ) {
                        if ( widePos1 < sizeof( wideString1 ) / sizeof( wchar_t ) - 1 ) {
                            wideString1[ widePos1++ ] = wideChar;
                        }
                    }
                    else {
                        if ( widePos1 >= 4 ) {
                            wideString1[ widePos1 ] = L'\0';
                            wprintf( L"%ls\n", wideString1 );
                        }
                        widePos1 = 0;
                    }
                }

            }

            if ( ( offset + i ) % 2 == 1 ) {
                if ( i + 1 < bytesRead ) {
                    wchar_t wideChar = buffer[ i ] | ( buffer[ i + 1 ] << 8 );

                    if ( wideChar >= 0x20 && wideChar <= 0x7E ) {
                        if ( widePos2 < sizeof( wideString2 ) / sizeof( wchar_t ) - 1 ) {
                            wideString2[ widePos2++ ] = wideChar;
                        }
                    }
                    else {
                        if ( widePos2 >= 4 ) {
                            wideString2[ widePos2 ] = L'\0';
                            wprintf( L"%ls\n", wideString2 );
                        }
                        widePos2 = 0;
                    }
                }
            }

        }
        offset += bytesRead;
        if ( offset >= fileSize ) break;

    }
    return 0;
}