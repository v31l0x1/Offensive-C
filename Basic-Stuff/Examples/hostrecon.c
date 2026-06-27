#include <windows.h>
#include <stdio.h>
#include <lmcons.h>
#include <sddl.h>
#include <iphlpapi.h>

#define PRINT_INFO(label, fmt, ...) printf("[+] %-25s: " fmt "\n", label, __VA_ARGS__)

typedef NTSTATUS( NTAPI* RTLGETVERSION )( _Out_ PVOID VersionInformation );

int main( void ) {
    // host

    CHAR HostName[ MAX_COMPUTERNAME_LENGTH + 1 ];
    DWORD HostNameSize = sizeof( HostName );

    if ( !GetComputerNameA( HostName, &HostNameSize ) ) {
        printf( "[-] GetComputerNameA failed error: %d\n", GetLastError() );
        return -1;
    }

    // printf( "[+] HostName%-20s: %s\n", "", HostName );
    PRINT_INFO( "HostName", "%s", HostName );

    // username

    // CHAR UserName[ UNLEN + 1 ];
    // DWORD UserNameSize = sizeof( UserName );

    // if ( !GetUserNameA( UserName, &UserNameSize ) ) {
    //     printf( "[-] GetUserNameA failed with error: %d\n", GetLastError() );
    //     return -1;
    // }

    // printf( "[+] UserName: %s\n", UserName );

    // Domain and SID

    HANDLE hToken = NULL;
    if ( !OpenProcessToken( ( HANDLE )-1, TOKEN_READ, &hToken ) ) {
        printf( "[-] OpenProcessToken failed with error: %d\n", GetLastError() );
    }

    DWORD dwTokenInfoSize = 0;

    GetTokenInformation( hToken, TokenUser, NULL, dwTokenInfoSize, &dwTokenInfoSize );

    PTOKEN_USER UserToken = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenInfoSize );

    if ( !GetTokenInformation( hToken, TokenUser, UserToken, dwTokenInfoSize, &dwTokenInfoSize ) ) {
        printf( "[-] GetTokenInfromation failed with error: %d\n", GetLastError() );
    }

    PSID pSid = UserToken->User.Sid;
    LPSTR lpUserName = NULL;
    LPSTR lpDomainName = NULL;
    DWORD dwUserNameSize = 0;
    DWORD dwDomainNameSize = 0;
    SID_NAME_USE SidType;

    LookupAccountSidA( NULL, pSid, NULL, &dwUserNameSize, NULL, &dwDomainNameSize, &SidType );

    lpUserName = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwUserNameSize );
    lpDomainName = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwDomainNameSize );

    if ( !LookupAccountSidA( NULL, pSid, lpUserName, &dwUserNameSize, lpDomainName, &dwDomainNameSize, &SidType ) ) {
        printf( "[-] LookupAccountSidA failed with error: %d\n", GetLastError() );
    }

    LPSTR lpSid = NULL;
    if ( !ConvertSidToStringSidA( pSid, &lpSid ) ) {
        printf( "[-] ConvertSidToStringSidA failed with error: %d", GetLastError() );
        return -1;
    }

    // printf( "[+] UserName: %s\n", lpUserName );
    // printf( "[+] Sid: %s\n", lpSid );
    // printf( "[+] Domain: %s\n", lpDomainName );

    PRINT_INFO( "UserName", "%s", lpUserName );
    PRINT_INFO( "Sid", "%s", lpSid );
    PRINT_INFO( "Domain", "%s", lpDomainName );

    //current working directory

    CHAR CurrentDirectory[ MAX_PATH + 1 ];
    DWORD CurrentDirectorySize = sizeof( CurrentDirectory );

    if ( !GetCurrentDirectoryA( CurrentDirectorySize, CurrentDirectory ) ) {
        printf( "[-] GetCurrentDiirectoryA failed with error: %d\n", GetLastError() );
        return -1;
    }

    // printf( "[+] Current Directory: %s\n", CurrentDirectory );
    PRINT_INFO( "Current Directory", "%s", CurrentDirectory );

    //exe name
    CHAR FileName[ MAX_PATH + 1 ];
    DWORD FileNameSize = sizeof( FileName );

    if ( !GetModuleFileNameA( NULL, FileName, FileNameSize ) ) {
        printf( "[-] GetModileFileNameA failed wit error: %d\n", GetLastError() );
        return -1;
    }

    // printf( "[+] Executable Path: %s\n", FileName );
    PRINT_INFO( "Executable Path", "%s", FileName );

    // process id & thread id
    // printf( "[+] Process Id: %d\n", GetCurrentProcessId() );
    // printf( "[+] Thread Id: %d\n", GetCurrentThreadId() );
    PRINT_INFO( "Process Id", "%d", GetCurrentProcessId() );
    PRINT_INFO( "Thread Id", "%d", GetCurrentThreadId() );

    // Os Version
    HMODULE hNtdll = GetModuleHandleA( "ntdll" );
    if ( !hNtdll ) {
        printf( "[-] GetModuleHandleA failed with error: %d\n", GetLastError() );
        return -1;
    }
    RTLGETVERSION RtlGetVersion = ( RTLGETVERSION )GetProcAddress( hNtdll, "RtlGetVersion" );
    if ( !RtlGetVersion ) {
        printf( "[-] GetProcAddressA failed with error: %d\n", GetLastError() );
        return -1;
    }

    RTL_OSVERSIONINFOEXW osinfo = { 0 };
    osinfo.dwOSVersionInfoSize = sizeof( osinfo );

    if ( RtlGetVersion( &osinfo ) == 0 ) {
        // printf( "[+] Os Version: %d.%d Build %d\n", osinfo.dwMajorVersion, osinfo.dwMinorVersion, osinfo.dwBuildNumber );
        PRINT_INFO( "Os Version", "%d.%d Build %d", osinfo.dwMajorVersion, osinfo.dwMinorVersion, osinfo.dwBuildNumber );
    }
    else {
        printf( "[-] RtlGetVersion failed with error %d\n", GetLastError() );
        return -1;
    }

    CloseHandle( hNtdll );

    // Local Time
    SYSTEMTIME Systemtime = { 0 };

    GetLocalTime( &Systemtime );
    // printf( "[+] Local Time: %d-%d-%d %d:%d:%d\n", Systemtime.wDay, Systemtime.wMonth, Systemtime.wYear, Systemtime.wHour, Systemtime.wMinute, Systemtime.wSecond );
    PRINT_INFO( "Local Time", "%d-%d-%d %d:%d:%d", Systemtime.wDay, Systemtime.wMonth, Systemtime.wYear, Systemtime.wHour, Systemtime.wMinute, Systemtime.wSecond );

    //Physical Memory Total & Available
    MEMORYSTATUS MemoryStatus = { 0 };

    GlobalMemoryStatus( &MemoryStatus );
    // printf( "[+] Total Physical Memory: %lld MB\n", MemoryStatus.dwTotalPhys / ( 1024 * 1024 ) );
    // printf( "[+] Available Physical Memory: %lld MB\n", MemoryStatus.dwAvailPhys / ( 1024 * 1024 ) );
    PRINT_INFO( "Total Physical Memory", "%lld MB", MemoryStatus.dwTotalPhys / ( 1024 * 1024 ) );
    PRINT_INFO( "Available Physical Memory", "%lld MB", MemoryStatus.dwAvailPhys / ( 1024 * 1024 ) );

    // Active Connections
    PMIB_TCPTABLE pTcpTable = NULL;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;

    dwRetVal = GetExtendedTcpTable( pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_BASIC_CONNECTIONS, 0 );

    pTcpTable = ( PMIB_TCPTABLE )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize );

    if ( GetExtendedTcpTable( pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_BASIC_CONNECTIONS, 0 ) != 0 ) {
        printf( "[-] GetExtendedTcpTable failed with error: %d\n", GetLastError() );
    }

    PRINT_INFO( "Active Connections", "%d", pTcpTable->dwNumEntries );
    for ( DWORD i = 0; i < pTcpTable->dwNumEntries; i++ ) {
        MIB_TCPROW row = pTcpTable->table[ i ];

        IN_ADDR localAddr, remoteAddr;
        localAddr.S_un.S_addr = row.dwLocalAddr;
        remoteAddr.S_un.S_addr = row.dwRemoteAddr;

        if ( row.dwState != MIB_TCP_STATE_LISTEN && row.dwState != MIB_TCP_STATE_CLOSED ) {
            printf( "    Local: %s:%d -> Remote: %s:%d\n",
                inet_ntoa( localAddr ),
                ntohs( ( u_short )row.dwLocalPort ),
                inet_ntoa( remoteAddr ),
                ntohs( ( u_short )row.dwRemotePort ) );
        }
    }

    // Installed Softwares

    PRINT_INFO( "Installed Softwares", "", "" );
    HKEY hKey;
    if ( RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey ) != 0 ) {
        printf( "[-] RegOpenKeyExA failed with error: %d\n", GetLastError() );
    }


    for ( DWORD i = 0; ;i++ ) {

        CHAR SubKeyName[ 256 ];
        DWORD SubKeyNameSize = sizeof( SubKeyName );

        if ( RegEnumKeyExA( hKey, i, SubKeyName, &SubKeyNameSize, NULL, NULL, NULL, NULL ) != 0 ) {
            break;
        }

        HKEY hSubKey;
        if ( RegOpenKeyExA( hKey, SubKeyName, 0, KEY_READ, &hSubKey ) != 0 ) {
            printf( "[-] RefOpenKeyExA failed with error: %d\n", GetLastError() );
            continue;
        }

        CHAR DisplayName[ 256 ];
        DWORD DisplayNameSize = sizeof( DisplayName );

        if ( RegQueryValueExA( hSubKey, "DisplayName", NULL, NULL, ( LPBYTE )DisplayName, &DisplayNameSize ) == 0 ) {
            // PRINT_INFO( "Installed Software", "%s", DisplayName );
            printf( "    %s\n", DisplayName );
        }

        RegCloseKey( hSubKey );
    }

    RegCloseKey( hKey );

    if ( RegOpenKeyExA( HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hKey ) != 0 ) {
        printf( "[-] RegOpenKeyExA failed with error: %d\n", GetLastError() );
    }

    CloseHandle( hNtdll );
    CloseHandle( hToken );
    HeapFree( GetProcessHeap(), 0, UserToken );
    HeapFree( GetProcessHeap(), 0, lpUserName );
    HeapFree( GetProcessHeap(), 0, lpDomainName );
    HeapFree( GetProcessHeap(), 0, lpSid );
    HeapFree( GetProcessHeap(), 0, pTcpTable );

    return 0;

}