#include <windows.h>
#include <stdio.h>
#include <lmcons.h>
#include <sddl.h>

// cl.exe /W4 /MT /GS- /Zl envinfo.c /link /SUBSYSTEM:CONSOLE /ENTRY:main kernel32.lib advapi32.lib

VOID write_string( const char* str ) {
    HANDLE h = GetStdHandle( STD_OUTPUT_HANDLE );
    DWORD written;
    size_t len = 0;
    while ( str[ len ] ) len++;
    WriteConsoleA( h, str, ( DWORD )len, &written, NULL );
}

VOID write_char( char c ) {
    HANDLE h = GetStdHandle( STD_OUTPUT_HANDLE );
    DWORD written;
    WriteConsoleA( h, &c, 1, &written, NULL );
}

VOID print_num( int num ) {
    char buf[ 32 ];
    int i = 0;
    unsigned int n = ( num < 0 ) ? ( unsigned int )( -num ) : ( unsigned int )num;

    do {
        buf[ i++ ] = '0' + ( n % 10 );
        n /= 10;
    } while ( n );

    if ( num < 0 ) write_char( '-' );
    while ( i-- ) write_char( buf[ i ] );
}

VOID MyPrintf( const char* fmt, ... ) {
    va_list args;
    va_start( args, fmt );

    while ( *fmt ) {
        if ( *fmt == '%' && *( fmt + 1 ) ) {
            fmt++;
            switch ( *fmt ) {
            case 'd': case 'i': print_num( va_arg( args, int ) ); break;
            case 's': write_string( va_arg( args, const char* ) ); break;
            case 'c': write_char( ( char )va_arg( args, int ) ); break;
            case '%': write_char( '%' ); break;
            default: write_char( '%' ); write_char( *fmt );
            }
        }
        else {
            write_char( *fmt );
        }
        fmt++;
    }
    va_end( args );
}

int main( void ) {
    char host[ 256 ];
    DWORD host_size = sizeof( host );

    if ( !GetComputerNameA( host, &host_size ) ) {
        MyPrintf( "[-] GetComputerNameA failed with error code: %lu\n", GetLastError() );
        return 0;
    }


    char user[ 256 + 1 ];
    DWORD user_size = sizeof( user );

    if ( !GetUserNameA( user, &user_size ) ) {
        MyPrintf( "[-] GetUserNameA failed with error code: %lu\n", GetLastError() );
        return 0;
    }

    HANDLE hToken = NULL;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_READ, &hToken ) ) {
        MyPrintf( "[-] OpenProcessToken failed with error code: %lu\n", GetLastError() );
        return 0;
    }

    DWORD dwTokenInfoSize = 0;
    GetTokenInformation( hToken, TokenUser, NULL, 0, &dwTokenInfoSize );

    PTOKEN_USER pTokenUser = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenInfoSize );

    if ( !pTokenUser ) {
        MyPrintf( "[-] Memory allocation failed\n" );
        goto cleanup;
    }

    if ( !GetTokenInformation( hToken, TokenUser, pTokenUser, sizeof( TokenUser ), &dwTokenInfoSize ) ) {
        MyPrintf( "[-] GetTokenInformation failed with error code: %lu\n", GetLastError() );
        goto cleanup;
    }

    CloseHandle( hToken );

    PSID pSid = pTokenUser->User.Sid;
    char* lpName = NULL;
    char* lpDomain = NULL;
    DWORD dwNameSize = 0;
    DWORD dwDomainSize = 0;
    SID_NAME_USE SidType;

    LookupAccountSidA( NULL, pSid, NULL, &dwNameSize, NULL, &dwDomainSize, &SidType );

    // lpName = malloc( dwNameSize * sizeof( char ) );
    // lpDomain = malloc( dwDomainSize * sizeof( char ) );

    lpName = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwNameSize * sizeof( char ) );
    lpDomain = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwDomainSize * sizeof( char ) );

    if ( !lpName || !lpDomain ) {
        MyPrintf( "[-] Memory allocation failed\n" );
        goto cleanup;
    }

    if ( !LookupAccountSidA( NULL, pSid, lpName, &dwNameSize, lpDomain, &dwDomainSize, &SidType ) ) {
        MyPrintf( "[-] LookupAccountSidA failed with error code: %lu\n", GetLastError() );
        goto cleanup;
    }

    LPSTR lpSid = NULL;
    if ( !ConvertSidToStringSidA( pSid, &lpSid ) ) {
        MyPrintf( "[-] ConvertSidToStringSidA failed with error code: %lu\n", GetLastError() );
        goto cleanup;
    }

    MyPrintf( "[+] Hostname    : %s\n", host );
    MyPrintf( "[+] Architecture: %s\n", sizeof( void* ) == 8 ? "x64" : "x86" );
    MyPrintf( "[+] Username    : %s\n", user );
    MyPrintf( "[+] Domain      : %s\n", lpDomain );
    MyPrintf( "[+] SID         : %s\n", lpSid );

    HANDLE outHandle = NULL;

    outHandle = GetStdHandle( STD_OUTPUT_HANDLE );
    if ( outHandle == INVALID_HANDLE_VALUE ) {
        MyPrintf( "[-] GetStdHandle failed with error code: %lu\n", GetLastError() );
        goto cleanup;
    }

    MyPrintf( "[+] Hostname    : %s\n", host );

cleanup:
    if ( pTokenUser ) HeapFree( GetProcessHeap(), 0, pTokenUser );
    if ( hToken ) CloseHandle( hToken );
    if ( lpName ) HeapFree( GetProcessHeap(), 0, lpName );
    if ( lpDomain ) HeapFree( GetProcessHeap(), 0, lpDomain );
    if ( lpSid ) LocalFree( lpSid );

    return 0;

}