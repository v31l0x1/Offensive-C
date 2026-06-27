#include <windows.h>
#include <stdio.h>

INT Wanted( LPCSTR fileName, LPCSTR extensions ) {
    LPCSTR dot = strrchr( fileName, '.' );
    if ( !dot ) return 0;
    if ( !extensions || !*extensions || extensions == NULL ) return 1;

    LPCSTR extList = extensions;
    while ( *extList ) {
        LPCSTR comma = strchr( extList, ',' );
        size_t extLen = comma ? ( size_t )( comma - extList ) : strlen( extList );
        if ( _strnicmp( dot + 1, extList, extLen ) == 0 && strlen( dot + 1 ) == extLen ) {
            return 1;
        }
        if ( !comma ) break;
        extList += extLen + 1;
    }
    return 0;
}

VOID Enum( LPCSTR filePath, LPCSTR extensions, int hidden ) {
    CHAR pattern[ MAX_PATH ];
    _snprintf_s( pattern, sizeof( pattern ), _TRUNCATE, "%s\\*.*", filePath );

    WIN32_FIND_DATAA findData = { 0 };
    HANDLE hFind = FindFirstFileA( pattern, &findData );
    if ( hFind == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "Error: Could not open directory %s\n", filePath );
    }

    do {
        if ( strcmp( findData.cFileName, "." ) == 0 || strcmp( findData.cFileName, ".." ) == 0 ) {
            continue;
        }

        if ( !hidden ) {
            DWORD attribute = findData.dwFileAttributes;
            if ( attribute & ( FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM ) ) {
                continue;
            }
        }

        CHAR full[ MAX_PATH ];
        _snprintf_s( full, sizeof( full ), _TRUNCATE, "%s\\%s", filePath, findData.cFileName );

        if ( findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) {
            if ( !findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT ) {
                Enum( full, extensions, hidden );
            }
        }
        else {

            if ( !Wanted( findData.cFileName, extensions ) ) {
                continue;
            }

            LARGE_INTEGER fileSize;
            fileSize.HighPart = findData.nFileSizeHigh;
            fileSize.LowPart = findData.nFileSizeLow;

            fprintf( stdout, "%-8lld %s\n", fileSize.QuadPart, findData.cFileName );
        }
    } while ( FindNextFileA( hFind, &findData ) );

    FindClose( hFind );
}

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <filepath> <extension> --with-hidden\n", argv[ 0 ] );
        return 1;
    }

    LPCSTR filePath = argv[ 1 ];
    LPCSTR extensions = argv[ 2 ];
    int hidden = 0;

    for ( int i = 3; i < argc; i++ ) {
        if ( strcmp( argv[ i ], "--hidden" ) == 0 ) {
            hidden = 1;
        }
    }

    Enum( filePath, extensions, hidden );


    return 0;
}