#include <windows.h>
#include <stdio.h>

int main( int argc, char* argv[] ) {

    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <path_to_pe_file>\n", argv[ 0 ] );
        return 1;
    }

    printf( "[+] Parsing PE file: %s\n", argv[ 1 ] );

    HANDLE hFile = CreateFileA( argv[ 1 ], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );
    if ( hFile == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "[-] CreateFileA failed with error: %lu\n", GetLastError() );
        return 1;
    }

    DWORD fileSize = GetFileSize( hFile, NULL );

    LPCSTR buffer = ( LPCSTR )HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, fileSize );
    if ( buffer == NULL ) {
        fprintf( stderr, "[-] HeapAlloc failed with error: %lu\n", GetLastError() );
        CloseHandle( hFile );
        return 1;
    }

    DWORD bytesRead;

    if ( !ReadFile( hFile, ( LPVOID )buffer, fileSize, &bytesRead, NULL ) || bytesRead != fileSize ) {
        fprintf( stderr, "[-] ReadFile failed with error: %lu\n", GetLastError() );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )buffer );
        CloseHandle( hFile );
        return 1;
    }

    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )buffer;
    if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid DOS signature: 0x%X\n", dosHeader->e_magic );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )buffer );
        CloseHandle( hFile );
        return 1;
    }

    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( buffer + dosHeader->e_lfanew );
    if ( ntHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        fprintf( stderr, "[-] Invalid NT signature: 0x%X\n", ntHeaders->Signature );
        HeapFree( GetProcessHeap(), 0, ( LPVOID )buffer );
        CloseHandle( hFile );
        return 1;
    }

    printf( "[+] Machine: %s\n", ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" : ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "Unknown" );
    printf( "[+] Number of Sections: %d\n", ntHeaders->FileHeader.NumberOfSections );
    printf( "[+] TimeDateStamp: 0x%X\n", ntHeaders->FileHeader.TimeDateStamp );

    printf( "[+] Entry Point: 0x%08X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint );
    printf( "[+] Preferred Base Address: 0x%llX\n", ntHeaders->OptionalHeader.ImageBase );
    printf( "[+] Size of Image: 0x%08X\n", ntHeaders->OptionalHeader.SizeOfImage );
    printf( "[+] Characteristics: 0x%04X\n", ntHeaders->OptionalHeader.DllCharacteristics );


    // Section Headers
    printf( "\n%-4s %-10s %-8s\n\n", "===", "Section Headers", "===" );
    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION( ntHeaders );

    for ( WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeaders++ ) {
        CHAR name[ 9 ] = { 0 };
        memcpy( name, sectionHeaders->Name, 8 );
        printf( "%-8s RVA=0x%08X VirtualSize=0x%08X RawAddress=0x%08X RawSize=0x%08X Characteristics=0x%08X\n",
            name,
            sectionHeaders->VirtualAddress,
            sectionHeaders->Misc.VirtualSize,
            sectionHeaders->PointerToRawData,
            sectionHeaders->SizeOfRawData,
            sectionHeaders->Characteristics );
    }

    // Imports
    printf( "\n%-4s %-10s %-8s\n\n", "===", "Import Address Table", "===" );
    PIMAGE_IMPORT_DESCRIPTOR imageDirectory = ( PIMAGE_IMPORT_DESCRIPTOR )( ( BYTE* )buffer + ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress );

    for ( ; imageDirectory->Name; imageDirectory++ ) {

        LPCSTR dllName = ( LPCSTR )( ( BYTE* )buffer + imageDirectory->Name );
        printf( "%s\n", dllName );

        PIMAGE_THUNK_DATA originalFirstThunk = ( PIMAGE_THUNK_DATA )( ( BYTE* )buffer + imageDirectory->OriginalFirstThunk );
        for ( ; originalFirstThunk->u1.AddressOfData; originalFirstThunk++ ) {
            if ( originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ) {
                printf( "    oridinal #%llu\n", originalFirstThunk->u1.Ordinal & 0xFFFF );
            }
            else {
                PIMAGE_IMPORT_BY_NAME importByName = ( PIMAGE_IMPORT_BY_NAME )( ( BYTE* )buffer + originalFirstThunk->u1.AddressOfData );
                printf( "    %s\n", importByName->Name );
            }
        }
    }


    // Exports
    printf( "\n%-4s %-10s %-8s\n\n", "===", "Exported Functions", "===" );
    DWORD exportDirectorRVA = ntHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    if ( exportDirectorRVA == 0 ) {
        printf( "[-] No export directory found\n" );
    }
    else {
        PIMAGE_EXPORT_DIRECTORY exportDirectory = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )buffer + exportDirectorRVA );

        PDWORD pFuncNames = ( PDWORD )( ( BYTE* )buffer + exportDirectory->AddressOfNames );
        PDWORD pFuncAddresses = ( PDWORD )( ( BYTE* )buffer + exportDirectory->AddressOfFunctions );
        PWORD pFuncNameOridinals = ( PWORD )( ( BYTE* )buffer + exportDirectory->AddressOfNameOrdinals );

        for ( DWORD i = 0; i < exportDirectory->NumberOfNames; i++ ) {
            LPCSTR pFuncName = ( LPCSTR )( ( BYTE* )buffer + pFuncNames[ i ] );
            printf( "%s -> RVA=0x%08X\n", pFuncName, pFuncAddresses[ pFuncNameOridinals[ i ] ] );
        }
    }


    HeapFree( GetProcessHeap(), 0, ( LPVOID )buffer );
    CloseHandle( hFile );
    return 0;
}