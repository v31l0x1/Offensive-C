#include <windows.h>
#include <stdio.h>

typedef int ( *Handler )( const char* args );

int help( const char* args );
int pid( const char* args );
int host( const char* args );
int echo( const char* args );
int winenum( const char* args );
int arch( const char* args );



typedef struct {
    const char* name;
    Handler* fn;
    const char* help;
} Command;


static const Command kCommands[] = {
    { "help", help, "List commands" },
    { "pid", pid, "Print current process ID" },
    { "host", host, "Print hostname" },
    { "arch", arch, "Print architecture" },
    { "echo", echo, "Echo command" },
    { "winenum", winenum, "Enumerate windows" }
};

static const size_t kNumCommands = sizeof( kCommands ) / sizeof( Command );

int help( const char* args ) {
    ( void )args;
    printf( "commands:\n" );
    for ( size_t i = 0; i < kNumCommands; ++i )
        printf( "  %s: %s\n", kCommands[ i ].name, kCommands[ i ].help );
    return 0;
}

int pid( const char* args ) {
    ( void )args;
    printf( "Pid = %lu\n", GetCurrentProcessId() );
    return 0;
}

int host( const char* args ) {
    ( void )args;
    char hostname[ 256 ];
    DWORD size = sizeof( hostname );
    if ( !GetComputerNameA( hostname, &size ) ) {
        fprintf( stderr, "[-] GetComputerNameA failed with error %lu\n", GetLastError() );
        return 1;
    }

    printf( "Hostname: %s\n", hostname );

    return 0;
}

int arch( const char* args ) {
    ( void )args;

    if ( sizeof( void* ) == 8 ) {
        printf( "Architecture: x64\n" );
    }
    else {
        printf( "Architecture: x86\n" );
    }
    return 0;
}

int echo( const char* args ) {
    ( void )args;
    printf( "Echo: %s\n", args ? args : "" );
    return 0;
}

BOOL CALLBACK EnumWindowsProc( HWND hwnd, LPARAM lParam ) {
    int* counter = ( int* )lParam;
    char title[ 256 ] = { 0 };
    if ( GetWindowTextA( hwnd, title, sizeof( title ) ) ) {
        printf( "Window: %s\n", title );
        ( *counter )++;
    }
    return TRUE;
}

int winenum( const char* args ) {
    ( void )args;
    int count = 0;
    if ( !EnumWindows( EnumWindowsProc, ( LPARAM )&count ) ) {
        fprintf( stderr, "[-] EnumWindows failed with error %lu\n", GetLastError() );
        return 1;
    }

    printf( "Total windows: %d\n", count );
    return 0;
}

static Handler lookup( const char* args ) {
    for ( size_t i = 0; i < kNumCommands; i++ ) {
        if ( _stricmp( args, kCommands[ i ].name ) == 0 ) {
            return kCommands[ i ].fn;
        }
    }
    return NULL;
}

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        printf( "Usage: %s command\n", argv[ 0 ] );
        return help( NULL );
    }

    Handler fn = lookup( argv[ 1 ] );

    if ( !fn ) {
        fprintf( stderr, "Unknown command: %s\n", argv[ 1 ] );
        return help( NULL );
    }

    const char* args = ( argc > 2 ) ? argv[ 2 ] : NULL;
    return fn( args );

}