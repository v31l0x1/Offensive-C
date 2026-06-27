#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdio.h>

#define PPEB_PTR __readgsqword(0x60)


HMODULE FindModule( const wchar_t* name ) {

    PPEB peb = ( PPEB )PPEB_PTR;
    PPEB_LDR_DATA pLdr = peb->Ldr;
    wprintf( L"[+] PEB: %p\n", peb );
    wprintf( L"[+] Ldr: %p\n", pLdr );

    // PLDR_DATA_TABLE_ENTRY pModule = ( PLDR_DATA_TABLE_ENTRY )pLdr->InMemoryOrderModuleList.Flink;

    // PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;

    PLIST_ENTRY pInLoadOrderModuleList = ( PLIST_ENTRY )( ( BYTE* )pLdr + 0x10 );
    PLIST_ENTRY pInMemoryOrderModuleList = ( PLIST_ENTRY )( ( BYTE* )pLdr + 0x20 );

    PLDR_DATA_TABLE_ENTRY pModule = ( PLDR_DATA_TABLE_ENTRY )pInMemoryOrderModuleList->Flink;

    PLDR_DATA_TABLE_ENTRY pFirstModule = pModule;
    do {
        if ( pModule->FullDllName.Buffer && !_wcsicmp( pModule->FullDllName.Buffer, name ) ) {
            wprintf( L"[+] Dll Name: %s\n", pModule->FullDllName.Buffer );
            wprintf( L"[+] Dll Base Address: 0x%p\n", pModule->Reserved2[ 0 ] );
            return ( HMODULE )pModule->Reserved2[ 0 ];
        }
        pModule = ( PLDR_DATA_TABLE_ENTRY )pModule->Reserved1[ 0 ];
    } while ( pModule && pModule != pFirstModule );


    // wprintf( L"[+] InLoadOrderModuleList: %p\n", pInLoadOrderModuleList->Flink );
    // wprintf( L"[+] InMemoryOrderModuleList: %p\n", pLdr->InMemoryOrderModuleList.Flink );

    // do {

    //     if ( pModule->FullDllName.Buffer && !_wcsicmp( pModule->FullDllName.Buffer, name ) ) {
    //         wprintf( L"[+] Dll Name: %s\n", pModule->FullDllName.Buffer );
    //         wprintf( L"[+] Dll Base Address: 0x%p\n", pModule->Reserved2[ 0 ] );
    //         return ( HMODULE )pModule->Reserved2[ 0 ];
    //     }
    //     pModule = ( PLDR_DATA_TABLE_ENTRY )pModule->Reserved1[ 0 ];
    // } while ( pModule && pModule != pFirstModule );

    // for ( PLIST_ENTRY pListEntry = pLdr->InMemoryOrderModuleList.Flink;
    //     pListEntry != &pLdr->InMemoryOrderModuleList;
    //     pListEntry = pListEntry->Flink
    //     ) {

    //     PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks );

    //     if ( pModule->FullDllName.Buffer && !_wcsicmp( pModule->FullDllName.Buffer, name ) ) {
    //         wprintf( L"[+] Dll's: %s\n", pModule->FullDllName.Buffer );
    //         wprintf( L"[+] Base Address: %p\n", pModule->DllBase );
    //         return ( HMODULE )pModule->DllBase;
    //     }
    // }

    return INVALID_HANDLE_VALUE;
}

FARPROC FindFunction( HMODULE hModule, const char* functionName ) {

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER )hModule;
    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE ) {
        wprintf( L"[-] Invalid DOS header\n" );
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )hModule + pDosHeader->e_lfanew );
    if ( pNtHeaders->Signature != IMAGE_NT_SIGNATURE ) {
        wprintf( L"[-] Invalid NT header\n" );
        return NULL;
    }

    DWORD exportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
    if ( exportDirRVA == 0 ) {
        wprintf( L"[-] No export directory\n" );
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = ( PIMAGE_EXPORT_DIRECTORY )( ( BYTE* )hModule + exportDirRVA );

    DWORD* pFuncNames = ( DWORD* )( ( BYTE* )hModule + pExportDir->AddressOfNames );
    DWORD* pFuncAddresses = ( DWORD* )( ( BYTE* )hModule + pExportDir->AddressOfFunctions );
    WORD* pFuncNameOrdinals = ( WORD* )( ( BYTE* )hModule + pExportDir->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < pExportDir->NumberOfNames; i++ ) {
        const char* pFuncName = ( const char* )( ( BYTE* )hModule + pFuncNames[ i ] );
        if ( strcmp( pFuncName, functionName ) == 0 ) {
            printf( "[+] Function Name: %s\n", pFuncName );
            DWORD funcRVA = pFuncAddresses[ pFuncNameOrdinals[ i ] ];
            return ( FARPROC )( ( BYTE* )hModule + funcRVA );
        }
    }

    return NULL;
}

int main() {
    FindModule( L"ntdll.dll" );

    HMODULE hModule = GetModuleHandleW( L"ntdll.dll" );

    wprintf( L"GetModuleHandle Address: 0x%p\n", hModule );

    HANDLE pNtAllocateVirtualMemory = FindFunction( hModule, "NtAllocateVirtualMemory" );
    printf( "[+] NtAllocateVirtualMemory Address: 0x%p\n", pNtAllocateVirtualMemory );

    printf( "GetProcAddress Address: 0x%p\n", GetProcAddress( hModule, "NtAllocateVirtualMemory" ) );
    return 0;
}