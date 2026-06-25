#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")


int ProbePort( const char* host, int port, DWORD timeout_ms ) {
    SOCKET s = socket( AF_INET, SOCK_STREAM, IPPROTO_TCP );
    if ( s == INVALID_SOCKET ) return -1;

    // Set up address
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons( ( u_short )port );
    if ( inet_pton( AF_INET, host, &addr.sin_addr ) != 1 ) {
        // Try resolving as hostname
        struct addrinfo hints = { 0 };
        struct addrinfo* result = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if ( getaddrinfo( host, NULL, &hints, &result ) != 0 ) {
            closesocket( s );
            return -1;
        }
        addr.sin_addr = ( ( struct sockaddr_in* )result->ai_addr )->sin_addr;
        freeaddrinfo( result );
    }

    // Non-blocking with manual timeout
    u_long mode = 1;
    ioctlsocket( s, FIONBIO, &mode );

    int rc = connect( s, ( struct sockaddr* )&addr, sizeof( addr ) );
    if ( rc == 0 ) {
        closesocket( s );
        return 1;
    }
    if ( WSAGetLastError() != WSAEWOULDBLOCK ) {
        closesocket( s );
        return 0;
    }

    fd_set wf, ef;
    FD_ZERO( &wf ); FD_SET( s, &wf );
    FD_ZERO( &ef ); FD_SET( s, &ef );
    struct timeval tv = { ( long )( timeout_ms / 1000 ),
                          ( long )( ( timeout_ms % 1000 ) * 1000 ) };
    int sel = select( 0, NULL, &wf, &ef, &tv );

    int result = 0;
    if ( sel > 0 ) {
        // Writability alone does not mean success.
        // Ask the socket whether the connect actually completed.
        int so_err = 0;
        int so_len = sizeof( so_err );
        if ( getsockopt( s, SOL_SOCKET, SO_ERROR,
            ( char* )&so_err, &so_len ) == 0 && so_err == 0 ) {
            result = 1;
        }
    }
    closesocket( s );
    return result;
}

int main( int argc, char* argv[] ) {

    if ( argc < 3 ) {
        fprintf( stderr, "Usage: %s <host> <port1, port2, ...> [timeout_ms]\n", argv[ 0 ] );
        return 1;
    }


    WSADATA wsaData;
    if ( WSAStartup( MAKEWORD( 2, 2 ), &wsaData ) != 0 ) {
        fprintf( stderr, "[-] WSAStartup failed with error: %d\n", WSAGetLastError() );
        return 1;
    }

    CONST CHAR* Host = argv[ 1 ];
    DWORD TimeOut = ( argc > 3 ) ? atoi( argv[ 3 ] ) : 800;


    CHAR* PortBuf[ 1024 ] = { 0 };
    strcpy_s( PortBuf, sizeof( PortBuf ), argv[ 2 ] );
    CHAR* Ctx = NULL;
    CHAR* Tok = strtok_s( PortBuf, ",", &Ctx );
    int OpenCount = 0;


    while ( Tok ) {
        int Port = atoi( Tok );
        if ( Port >= 1 && Port <= 65535 ) {
            int Rc = ProbePort( Host, Port, TimeOut );
            CONST CHAR* Status = ( Rc == 1 ) ? "OPEN" : ( Rc == 0 ) ? "CLOSED" : "ERROR";
            printf( "[%s] %s:%d\n", Status, Host, Port );
            if ( Rc == 1 ) {
                OpenCount++;
            }
        }
        Tok = strtok_s( NULL, ",", &Ctx );
    }

    printf( "[+] Total open ports: %d\n", OpenCount );
    WSACleanup();
    return 0;

}