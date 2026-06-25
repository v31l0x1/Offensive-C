#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// VOID EnumProc( void ) {

//     HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

//     PROCESSENTRY32 pe32;
//     pe32.dwSize = sizeof( PROCESSENTRY32 );
//     printf( "%-10s %-20s %-10s\n", "PID", "Name", "Path" );
//     printf( "---------------------------------------------------\n" );
//     if ( Process32First( hSnapshot, &pe32 ) ) {
//         do {
//             HANDLE hProc = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID );
//             if ( hProc ) {
//                 CHAR szFileName[ MAX_PATH ] = { 0 };
//                 DWORD dwSize = sizeof( szFileName );
//                 if ( QueryFullProcessImageNameA( hProc, 0, szFileName, &dwSize ) ) {
//                     printf( "%-10d %-20s %-10s\n", pe32.th32ProcessID, pe32.szExeFile, szFileName );
//                 }
//             }

//         } while ( Process32Next( hSnapshot, &pe32 ) );
//     }

//     CloseHandle( hSnapshot );
// }

int main( int argc, char* argv[] ) {


    if ( argc < 2 ) {
        fprintf( stderr, "Usage: \n" );
        fprintf( stderr, "  %s run \"<command line>\"\n", argv[ 0 ] );
        fprintf( stderr, "  %s pid <pid>\n", argv[ 0 ] );
        return 1;
    }

    if ( strcmp( argv[ 1 ], "run" ) == 0 ) {
        if ( argc < 3 ) {
            fprintf( stderr, "Usage: %s run \"<command line>\"\n", argv[ 0 ] );
            return 1;
        }
        else {
            CHAR cmdLine[ 1024 ] = { 0 };
            memcpy( cmdLine, argv[ 2 ], sizeof( cmdLine ) - 1 );
            SECURITY_ATTRIBUTES sa = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
            HANDLE hRead, hWrite = NULL;
            if ( !CreatePipe( &hRead, &hWrite, &sa, 0 ) ) {
                fprintf( stderr, "Failed to create pipe\n" );
                return 1;
            }
            SetHandleInformation( hRead, HANDLE_FLAG_INHERIT, 0 );

            STARTUPINFOA si = { 0 };
            si.cb = sizeof( STARTUPINFOA );
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.hStdInput = NULL;

            PROCESS_INFORMATION pi = { 0 };
            if ( !CreateProcessA( NULL, cmdLine, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi ) ) {
                fprintf( stderr, "[!] CreateProcessA failed with error: %lu\n", GetLastError() );
                CloseHandle( hRead );
                CloseHandle( hWrite );
                return 1;
            }

            CloseHandle( hWrite );

            BYTE buffer[ 4096 ];
            DWORD bytesRead;
            while ( ReadFile( hRead, buffer, sizeof( buffer ) - 1, &bytesRead, NULL ) && bytesRead > 0 ) {
                fwrite( buffer, 1, bytesRead, stdout );
            }
            CloseHandle( hRead );

            WaitForSingleObject( pi.hProcess, INFINITE );
            // DWORD exitCode;
            // GetExitCodeProcess( pi.hProcess, &exitCode );
            CloseHandle( pi.hProcess );
            // CloseHandle( pi.hThread );
            // printf( "\nProcess exited with code: %lu\n", exitCode );
        }
    }

    if ( strcmp( argv[ 1 ], "pid" ) == 0 ) {
        if ( argc < 3 ) {
            fprintf( stderr, "Usage: %s pid <pid>\n", argv[ 0 ] );
            return 1;
        }
        else {
            DWORD pid = atoi( argv[ 2 ] );
            HANDLE hProc = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
            if ( hProc ) {
                CHAR szFileName[ MAX_PATH ] = { 0 };
                DWORD dwSize = sizeof( szFileName );
                if ( QueryFullProcessImageNameA( hProc, 0, szFileName, &dwSize ) ) {
                    printf( "PID: %d\n", pid );
                    printf( "Path: %s\n", szFileName );
                }
                CloseHandle( hProc );
            }
            else {
                fprintf( stderr, "Failed to open process with PID %d\n", pid );
                return 1;
            }
        }
    }

    return 0;

}