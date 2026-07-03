#include <windows.h>
#include <stdio.h>
#include <winternl.h>   

#define GetPeb() ((PPEB)__readgsqword(0x60))


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

HMODULE MyGetModuleHandle( LPCWSTR lpModuleName ) {
    PPEB peb = GetPeb();
    PLIST_ENTRY moduleList = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY currentEntry = moduleList->Flink;

    while ( currentEntry != moduleList ) {
        PLDR_DATA_TABLE_ENTRY_ entry = CONTAINING_RECORD( currentEntry, LDR_DATA_TABLE_ENTRY_, InMemoryOrderLinks );
        // wprintf( L"Loaded Module: %s\n", entry->BaseDllName.Buffer );
        if ( entry->BaseDllName.Buffer && _wcsicmp( entry->BaseDllName.Buffer, lpModuleName ) == 0 ) {
            return ( HMODULE )entry->DllBase;
        }
        currentEntry = currentEntry->Flink;
    }
    return NULL;
}

int main() {

    LPCWSTR moduleName = L"kernel32.dll";
    HMODULE hModule = MyGetModuleHandle( moduleName );

    if ( hModule ) {
        wprintf( L"[+] Module %s found at address: 0x%p\n", moduleName, hModule );
    }
    else {
        wprintf( L"[-] Module %s not found.\n", moduleName );
    }

    return 0;
}