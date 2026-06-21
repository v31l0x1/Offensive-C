#include <windows.h>
#include <stdio.h> 

VOID EnumSoftware( void ) {

    HKEY hUninstall;

    LSTATUS lStatus = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0, KEY_READ, &hUninstall );

    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to open registry key: %ld\n", lStatus );
        return;
    }


    DWORD dwIndex = 0;
    CHAR szSubKeyName[ 256 ];
    DWORD dwSubKeyNameSize;
    DWORD dwCount = 0;

    printf( "Installed Software:\n" );
    while ( TRUE ) {
        dwSubKeyNameSize = sizeof( szSubKeyName );

        lStatus = RegEnumKeyExA( hUninstall, dwIndex++, szSubKeyName, &dwSubKeyNameSize, NULL, NULL, NULL, NULL );

        if ( lStatus == ERROR_NO_MORE_ITEMS ) {
            break;
        }
        else if ( lStatus != ERROR_SUCCESS ) {
            fprintf( stderr, "[!] Failed to enumerate subkeys: %ld\n", lStatus );
            break;
        }

        HKEY hChlidKey;
        if ( RegOpenKeyExA( hUninstall, szSubKeyName, 0, KEY_READ, &hChlidKey ) != ERROR_SUCCESS ) {
            continue;
        }

        CHAR szDisplayName[ 256 ];
        DWORD dwDisplayNameSize = sizeof( szDisplayName );
        DWORD type;
        if ( RegQueryValueExA( hChlidKey, "DisplayName", NULL, &type, ( LPBYTE )szDisplayName, &dwDisplayNameSize ) == ERROR_SUCCESS ) {
            printf( "   %s\n", szDisplayName );
            dwCount++;
        }

        RegCloseKey( hChlidKey );
    }

    printf( "Total installed software: %lu\n", dwCount );
    RegCloseKey( hUninstall );
}

VOID ListRunEntries( HKEY hRootKey ) {
    HKEY hRunKey;
    LSTATUS lStatus = RegOpenKeyExA( hRootKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hRunKey );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to open Run registry key: %ld\n", lStatus );
        return;
    }

    DWORD dwIndex = 0;
    CHAR szValueName[ 256 ];
    CHAR szValueData[ 1024 ];
    DWORD dwValueNameSize;
    DWORD dwCount = 0;
    DWORD dwType, dwDataSize;

    while ( TRUE ) {
        dwValueNameSize = sizeof( szValueName );
        dwDataSize = sizeof( szValueData );

        lStatus = RegEnumValueA( hRunKey, dwIndex++, szValueName, &dwValueNameSize, NULL, &dwType, ( LPBYTE )szValueData, &dwDataSize );
        if ( lStatus == ERROR_NO_MORE_ITEMS ) {
            break;
        }
        else if ( lStatus != ERROR_SUCCESS ) {
            fprintf( stderr, "[!] Failed to enumerate Run entries: %ld\n", lStatus );
            break;
        }

        if ( dwType == REG_SZ || dwType == REG_EXPAND_SZ ) {
            printf( "%s : %s\n", szValueName, szValueData );
            dwCount++;
        }
    }
    RegCloseKey( hRunKey );

}

VOID WriteCleanRegistryEntries( void ) {
    HKEY hMyKey;
    DWORD dwDisposition;

    LSTATUS lStatus = RegCreateKeyExA( HKEY_CURRENT_USER, "SOFTWARE\\MyTempRegsitry", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hMyKey, &dwDisposition );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to create registry key: %ld\n", lStatus );
        return;
    }

    LPCSTR lpValue = "This is a test data";
    lStatus = RegSetValueExA( hMyKey, "Test", 0, REG_SZ, ( LPBYTE )lpValue, ( DWORD )strlen( lpValue ) + 1 );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to set registry value: %ld\n", lStatus );
    }
    else {
        printf( "\n[+] Wrote Data to HKCU\\SOFTWARE\\MyTempRegistry (%s)\n", dwDisposition == REG_CREATED_NEW_KEY ? "Created New Key" : "Opened Existing Key" );
    }
    // RegCloseKey( hMyKey );

    // Cleanup

    lStatus = RegDeleteKeyA( HKEY_CURRENT_USER, "SOFTWARE\\MyTempRegsitry" );

    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to delete Key: %ld\n", lStatus );
    }
    else {
        printf( "[+] Deleted key HKCU\\SOFTWARE\\MyTempRegistry\n" );
    }
}

VOID RunPersistence( HKEY hRootKey, LPCSTR lpBinaryPath ) {
    HKEY hRunKey;

    LSTATUS lStatus = RegOpenKeyExA( hRootKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hRunKey );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to open Run registry key: %ld\n", lStatus );
        return;
    }

    LPCSTR lpValueName = lpBinaryPath;
    lStatus = RegSetValueExA( hRunKey, "RegPersistence", 0, REG_SZ, ( LPBYTE )lpValueName, ( DWORD )strlen( lpValueName ) + 1 );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to set Run registry value: %ld\n", lStatus );
    }
    else {
        printf( "[+] Added Run entry for persistence: %s\n", lpValueName );
    }
    RegCloseKey( hRunKey );
}

VOID RemovePersistence( HKEY hRootKey ) {
    HKEY hRunKey;

    LSTATUS lStatus = RegOpenKeyExA( hRootKey, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hRunKey );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to open Run registry key: %ld\n", lStatus );
        return;
    }

    lStatus = RegDeleteValueA( hRunKey, "RegPersistence" );
    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to delete Run registry value: %ld\n", lStatus );
    }
    else {
        printf( "[+] Removed Run entry for persistence\n" );
    }
    RegCloseKey( hRunKey );
}

VOID EnumStartType( DWORD dwStartType ) {
    switch ( dwStartType ) {
    case SERVICE_BOOT_START:
        printf( "  Type: Boot Start\n" );
        break;
    case SERVICE_SYSTEM_START:
        printf( "  Type: System Start\n" );
        break;
    case SERVICE_AUTO_START:
        printf( "  Type: Automatic Start\n" );
        break;
    case SERVICE_DEMAND_START:
        printf( "  Type: Demand Start\n" );
        break;
    case SERVICE_DISABLED:
        printf( "  Type: Disabled\n" );
        break;
    default:
        printf( "  Type: Unknown Start Type\n" );
    }
}

VOID EnumServices( void ) {
    HKEY hServicesKey;

    LSTATUS lStatus = RegOpenKeyExA( HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hServicesKey );

    if ( lStatus != ERROR_SUCCESS ) {
        fprintf( stderr, "[!] Failed to open Services registry key: %ld\n", lStatus );
        return;
    }

    DWORD dwIndex = 0;
    CHAR szSubKeyName[ 256 ];
    DWORD dwSubKeyNameSize;

    while ( TRUE ) {
        dwSubKeyNameSize = sizeof( szSubKeyName );

        lStatus = RegEnumKeyExA( hServicesKey, dwIndex++, szSubKeyName, &dwSubKeyNameSize, NULL, NULL, NULL, NULL );
        if ( lStatus == ERROR_NO_MORE_ITEMS ) {
            break;
        }
        else if ( lStatus != ERROR_SUCCESS ) {
            fprintf( stderr, "[!] Failed to enumerate Services subkeys: %ld\n", lStatus );
            break;
        }

        HKEY hChlidKey;
        if ( RegOpenKeyExA( hServicesKey, szSubKeyName, 0, KEY_READ, &hChlidKey ) != ERROR_SUCCESS ) {
            continue;
        }

        CHAR szImagePath[ 256 ];
        DWORD dwImagePathSize = sizeof( szImagePath );
        DWORD dwType;
        if ( RegQueryValueExA( hChlidKey, "ImagePath", NULL, &dwType, ( LPBYTE )szImagePath, &dwImagePathSize ) == ERROR_SUCCESS && ( dwType == REG_SZ || dwType == REG_EXPAND_SZ ) ) {
            printf( "%-20s\n", szSubKeyName );
            printf( "  Path: %s\n", szImagePath );

            DWORD dwStartType;
            DWORD dwStartTypeSize = sizeof( dwStartType );
            if ( RegQueryValueExA( hChlidKey, "Start", NULL, &dwType, ( LPBYTE )&dwStartType, &dwStartTypeSize ) == ERROR_SUCCESS ) {
                EnumStartType( dwStartType );
            }

        }
        RegCloseKey( hChlidKey );
    }
    RegCloseKey( hServicesKey );
}


int main() {

    // EnumSoftware();
    // printf( "\nEnumerating Run entries:\n" );
    // ListRunEntries( HKEY_LOCAL_MACHINE );
    // ListRunEntries( HKEY_CURRENT_USER );

    // WriteCleanRegistryEntries();

    // RunPersistence( HKEY_LOCAL_MACHINE, "C:\\Windows\\System32\\cmd.exe" );
    // RunPersistence( HKEY_CURRENT_USER, "C:\\Windows\\System32\\notepad.exe" );

    // RemovePersistence( HKEY_LOCAL_MACHINE );
    // RemovePersistence( HKEY_CURRENT_USER );

    EnumServices();

    return 0;
}