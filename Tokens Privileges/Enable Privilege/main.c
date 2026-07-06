#include <windows.h>
#include <stdio.h>

BOOL EnablePrivilege( LPCSTR privilegeName ) {

    HANDLE hToken;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) {
        printf( "OpenProcessToken failed. Error: %lu\n", GetLastError() );
        return FALSE;
    }

    LUID luid;
    if ( !LookupPrivilegeValueA( NULL, privilegeName, &luid ) ) {
        printf( "LookupPrivilegeValue failed. Error: %lu\n", GetLastError() );
        CloseHandle( hToken );
        return FALSE;
    }

    TOKEN_PRIVILEGES tokenPrivileges = { 0 };
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[ 0 ].Luid = luid;
    tokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges( hToken, FALSE, &tokenPrivileges, sizeof( TOKEN_PRIVILEGES ), NULL, NULL ) ) {
        printf( "AdjustTokenPrivileges failed. Error: %lu\n", GetLastError() );
        CloseHandle( hToken );
        return FALSE;
    }

    DWORD error = GetLastError();
    if ( error == ERROR_NOT_ALL_ASSIGNED ) {
        printf( "The token does not have the specified privilege. Error: %lu\n", error );
        CloseHandle( hToken );
        return FALSE;
    }

    CloseHandle( hToken );

    return TRUE;
}


VOID ListPrivilege() {

    HANDLE hToken;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) ) {
        printf( "OpenProcessToken failed. Error: %lu\n", GetLastError() );
        return;
    }

    DWORD dwSize = 0;
    GetTokenInformation( hToken, TokenPrivileges, NULL, 0, &dwSize );
    if ( GetLastError() != ERROR_INSUFFICIENT_BUFFER ) {
        printf( "GetTokenInformation failed. Error: %lu\n", GetLastError() );
        CloseHandle( hToken );
        return;
    }
    PTOKEN_PRIVILEGES pTokenPrivileges = ( PTOKEN_PRIVILEGES )malloc( dwSize );
    if ( !GetTokenInformation( hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize ) ) {
        printf( "GetTokenInformation failed. Error: %lu\n", GetLastError() );
        free( pTokenPrivileges );
        CloseHandle( hToken );
        return;
    }

    printf( "Privileges:\n" );
    for ( DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++ ) {
        LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[ i ];
        char privilegeName[ 256 ];
        DWORD nameSize = sizeof( privilegeName );
        if ( LookupPrivilegeNameA( NULL, &laa.Luid, privilegeName, &nameSize ) ) {
            printf( "  %s: %s\n", privilegeName, ( laa.Attributes & SE_PRIVILEGE_ENABLED ) ? "Enabled" : "Disabled" );
        }
        else {
            printf( "  Unknown privilege (LUID: %lu:%lu): %s\n", laa.Luid.HighPart, laa.Luid.LowPart, ( laa.Attributes & SE_PRIVILEGE_ENABLED ) ? "Enabled" : "Disabled" );
        }
    }
}

int main( void ) {

    if ( EnablePrivilege( "SeDebugPrivilege" ) ) {
        printf( "[+] SeDebugPrivilege enabled successfully.\n" );
    }
    else {
        printf( "[-] Failed to enable SeDebugPrivilege.\n" );
    }

    ListPrivilege();

    return 0;
}