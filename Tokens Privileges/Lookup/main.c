#include <windows.h>
#include <stdio.h>
#include <sddl.h>

LPCSTR GetPrivilegeAttributes( DWORD Attributes ) {
    if ( Attributes & SE_PRIVILEGE_ENABLED ) {
        return "Enabled";
    }
    else if ( Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT ) {
        return "Enabled by default";
    }
    else if ( Attributes & SE_PRIVILEGE_REMOVED ) {
        return "Removed";
    }
    else if ( Attributes & SE_PRIVILEGE_USED_FOR_ACCESS ) {
        return "Used for access";
    }
    else {
        return "Disabled";
    }
}

int main( void ) {

    HANDLE hToken = NULL;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY, &hToken ) ) {
        printf( "Failed to open process token. Error: %lu\n", GetLastError() );
        return 1;
    }

    DWORD dwSize = 0;
    GetTokenInformation( hToken, TokenUser, NULL, 0, &dwSize );
    PTOKEN_USER pTokenUser = ( PTOKEN_USER )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize );
    if ( !GetTokenInformation( hToken, TokenUser, pTokenUser, dwSize, &dwSize ) ) {
        printf( "Failed to get token information. Error: %lu\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenUser );
        CloseHandle( hToken );
        return 1;
    }

    LPSTR sidString = NULL;
    ConvertSidToStringSidA( pTokenUser->User.Sid, &sidString );
    // printf( "Current user SID: %s\n", sidString );

    CHAR Name[ 256 ] = { 0 };
    CHAR Domain[ 256 ] = { 0 };
    DWORD NameSize = sizeof( Name );
    DWORD DomainSize = sizeof( Domain );
    SID_NAME_USE SidType;
    if ( !LookupAccountSidA( NULL, pTokenUser->User.Sid, Name, &NameSize, Domain, &DomainSize, &SidType ) ) {
        printf( "Failed to lookup account SID. Error: %lu\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenUser );
        CloseHandle( hToken );
        return 1;
    }
    printf( "Current user: %s\\%s\n", Domain, Name );
    printf( "Current user SID: %s\n", sidString );

    HeapFree( GetProcessHeap(), 0, pTokenUser );

    dwSize = 0;
    GetTokenInformation( hToken, TokenIntegrityLevel, NULL, 0, &dwSize );
    PTOKEN_MANDATORY_LABEL pTIL = ( PTOKEN_MANDATORY_LABEL )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize );
    if ( !GetTokenInformation( hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize ) ) {
        printf( "Failed to get token integrity level. Error: %lu\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTIL );
        CloseHandle( hToken );
        return 1;
    }
    DWORD dwIntegrityLevel = *GetSidSubAuthority( pTIL->Label.Sid, ( DWORD )( UCHAR )( *GetSidSubAuthorityCount( pTIL->Label.Sid ) - 1 ) );
    LPCSTR Integrity = "UNKNOWN";
    if ( dwIntegrityLevel == SECURITY_MANDATORY_UNTRUSTED_RID ) {
        Integrity = "Untrusted";
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID ) {
        Integrity = "Low";
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_MEDIUM_RID ) {
        Integrity = "Medium";
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_HIGH_RID ) {
        Integrity = "High";
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_SYSTEM_RID ) {
        Integrity = "System";
    }
    else if ( dwIntegrityLevel == SECURITY_MANDATORY_PROTECTED_PROCESS_RID ) {
        Integrity = "Protected Process";
    }
    printf( "Current integrity level: %s\n", Integrity );

    HeapFree( GetProcessHeap(), 0, pTIL );

    dwSize = 0;
    GetTokenInformation( hToken, TokenPrivileges, NULL, 0, &dwSize );
    PTOKEN_PRIVILEGES pTokenPrivileges = ( PTOKEN_PRIVILEGES )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize );
    if ( !GetTokenInformation( hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize ) ) {
        printf( "Failed to get token privileges. Error: %lu\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenPrivileges );
        CloseHandle( hToken );
        return 1;
    }
    printf( "Current token privileges:\n" );
    for ( DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++ ) {
        CHAR privilegeName[ 256 ] = { 0 };
        DWORD dwprivilegeSize = sizeof( privilegeName );
        LookupPrivilegeNameA( NULL, &pTokenPrivileges->Privileges[ i ].Luid, privilegeName, &dwprivilegeSize );
        printf( "[+] %-42s  %s\n", privilegeName, GetPrivilegeAttributes( pTokenPrivileges->Privileges[ i ].Attributes ) );
    }
    HeapFree( GetProcessHeap(), 0, pTokenPrivileges );


    CloseHandle( hToken );

    return 0;
}