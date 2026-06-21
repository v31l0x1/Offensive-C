#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

char* state_name( DWORD state ) {
    switch ( state )
    {
    case MEM_COMMIT: return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE: return "MEM_FREE";
    default:
        return "Other";
    }
}

char* type_protect( DWORD state ) {
    switch ( state )
    {
    case PAGE_NOACCESS: return "PAGE_NOACCESS";
    case PAGE_READONLY: return "PAGE_READONLY";
    case PAGE_READWRITE: return "PAGE_READWRITE";
    case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
    case PAGE_EXECUTE: return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
    case PAGE_GUARD: return "PAGE_GUARD";
    case PAGE_NOCACHE: return "PAGE_NOCACHE";
    case PAGE_WRITECOMBINE: return "PAGE_WRITECOMBINE";
    default:
        return "Other";
    }
}

char* type_name( DWORD type ) {
    switch ( type )
    {
    case MEM_IMAGE:
        return "MEM_IMAGE";
    case MEM_MAPPED:
        return "MEM_MAPPED";
    case MEM_PRIVATE:
        return "MEM_PRIVATE";
    case 0:
        return "-";
    default:
        return "Other";
    }
}

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <process_name>\n", argv[ 0 ] );
        return 1;
    }

    LPCSTR processName = argv[ 1 ];

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "Failed to create snapshot: %lu\n", GetLastError() );
        goto cleanup;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    HANDLE hProcess = NULL;

    if ( !Process32First( hSnapshot, &pe32 ) ) {
        fprintf( stderr, "Failed to get first process: %lu\n", GetLastError() );
        goto cleanup;
    }

    do {
        if ( stricmp( pe32.szExeFile, processName ) == 0 ) {
            printf( "Found process: %s (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID );
            hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID );
            if ( hProcess == NULL ) {
                fprintf( stderr, "Failed to open process: %lu\n", GetLastError() );
                goto cleanup;
            }

        }
    } while ( Process32Next( hSnapshot, &pe32 ) );

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = NULL;
    while ( VirtualQueryEx( hProcess, addr, &mbi, sizeof( mbi ) ) ) {
        // if ( mbi.Type == MEM_IMAGE ) {
        //     char moduleName[ MAX_PATH ];
        //     GetModuleFileNameExA( hProcess, ( HMODULE )mbi.BaseAddress, moduleName, sizeof( moduleName ) );
        //     printf( "BaseAddress: %p RegionSize: 0x%016llX State: %-11s Protection: %-17s Type: %-11s\n",
        //         mbi.BaseAddress,
        //         mbi.RegionSize,
        //         state_name( mbi.State ),
        //         type_protect( mbi.Protect ),
        //         type_name( mbi.Type ) );
        // }
        // else {
        printf( "BaseAddress: 0x%p RegionSize: 0x%016llX State: %-11s Protection: %-17s Type: %-11s\n",
            mbi.BaseAddress,
            mbi.RegionSize,
            state_name( mbi.State ),
            type_protect( mbi.Protect ),
            type_name( mbi.Type ) );
        // }


        addr = ( LPVOID )( ( SIZE_T )mbi.BaseAddress + mbi.RegionSize );
    }


cleanup:
    if ( hSnapshot ) CloseHandle( hSnapshot );
    if ( hProcess ) CloseHandle( hProcess );

    return 0;
}