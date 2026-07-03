#include <windows.h>
#include <stdio.h>
#include <winternl.h>   

#define GetPeb() ((PPEB)__readgsqword(0x60))

#define RESOLVE_API(name, signature, hModHash, funcHash) \
    signature name = (signature)MyGetProcAddress(MyGetModuleHandle(hModHash), funcHash); \
    if (!name) { \
        fprintf(stderr, "[-] Failed to resolve API: %s\n", #name); \
        return 1; \
    } 

typedef HMODULE( WINAPI* fnLoadLibraryA )( LPCSTR lpLibFileName );

#define HASH_KEY 5381

#define KERNEL32_HASH 0x000000000002B5F0
#define LOADLIBRARYA_HASH 0x00000000B7072FDB

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
        if ( HashString( functionaName, 0, TRUE ) == Hash ) {
            return ( PVOID )( ( BYTE* )hModule + pAddressOfFunctions[ pAddressOfNameOrdinals[ i ] ] );
        }
    }
    return NULL;
}

int main() {

    LPCWSTR sKernel32 = L"kernel32.dll";
    // UINT_PTR hashKernel32 = HashString( sKernel32, 0, TRUE );
    // printf( "[+] Hash of %ls: 0x%p\n", sKernel32, hashKernel32 );
    HMODULE hKernel32 = MyGetModuleHandle( KERNEL32_HASH );

    if ( !hKernel32 ) {
        fprintf( stderr, "[-] Failed to resolve module: %ls\n", sKernel32 );
        return 1;
    }

    printf( "[+] Module %ls found at address: 0x%p\n", sKernel32, hKernel32 );

    // UINT_PTR hashLoadLibraryA = HashString( "LoadLibraryA", 0, TRUE );
    // printf( "[+] Hash of LoadLibraryA: 0x%p\n", hashLoadLibraryA );
    RESOLVE_API( pLoadLibraryA, fnLoadLibraryA, KERNEL32_HASH, LOADLIBRARYA_HASH );

    HMODULE hUser32 = pLoadLibraryA( "user32.dll" );
    if ( !hUser32 ) {
        fprintf( stderr, "[-] Failed to load module: user32.dll\n" );
        return 1;
    }
    printf( "[+] Module user32.dll loaded at address: 0x%p\n", hUser32 );

    return 0;
}