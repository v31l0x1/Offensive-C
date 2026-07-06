#include <windows.h>
#include <stdio.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)
#define OBJ_CASE_INSENSITIVE                0x00000040L

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_( MaximumLength, Length ) PWCH Buffer;
} UNICODE_STRING, * PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PSECURITY_DESCRIPTOR SecurityDescriptor;
    PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef const OBJECT_ATTRIBUTES* PCOBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
    ViewShare = 1, // The mapped view of the section will be mapped into any child processes created by the process.
    ViewUnmap = 2  // The mapped view of the section will not be mapped into any child processes created by the process.
} SECTION_INHERIT;

typedef NTSTATUS( NTAPI* fnNtOpenSection )(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PCOBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS( NTAPI* fnNtMapViewOfSection )(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG AllocationType,
    ULONG PageProtection
    );

typedef NTSTATUS( NTAPI* fnNtUnmapViewOfSection )(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
    );


int main( void ) {

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

    fnNtOpenSection NtOpenSection = ( fnNtOpenSection )GetProcAddress( hNtdll, "NtOpenSection" );
    fnNtMapViewOfSection NtMapViewOfSection = ( fnNtMapViewOfSection )GetProcAddress( hNtdll, "NtMapViewOfSection" );
    fnNtUnmapViewOfSection NtUnmapViewOfSection = ( fnNtUnmapViewOfSection )GetProcAddress( hNtdll, "NtUnmapViewOfSection" );

    UNICODE_STRING sectionName;
    sectionName.Buffer = L"\\KnownDlls\\ntdll.dll";
    sectionName.Length = ( USHORT )( wcslen( sectionName.Buffer ) * sizeof( WCHAR ) );
    sectionName.MaximumLength = sectionName.Length + sizeof( WCHAR );

    OBJECT_ATTRIBUTES objectAttributes;
    objectAttributes.Length = sizeof( OBJECT_ATTRIBUTES );
    objectAttributes.RootDirectory = NULL;
    objectAttributes.ObjectName = &sectionName;
    objectAttributes.Attributes = OBJ_CASE_INSENSITIVE;
    objectAttributes.SecurityDescriptor = NULL;
    objectAttributes.SecurityQualityOfService = NULL;


    HANDLE hSection = NULL;
    SIZE_T viewSize = 0;
    PVOID baseAddress = NULL;
    NTSTATUS status;

    status = NtOpenSection( &hSection, SECTION_MAP_READ, &objectAttributes );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "NtOpenSection failed with status: 0x%X\n", status );
        return 1;
    }

    status = NtMapViewOfSection( hSection, GetCurrentProcess(), &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READONLY );
    if ( !NT_SUCCESS( status ) ) {
        fprintf( stderr, "NtMapViewOfSection failed with status: 0x%X\n", status );
        return 1;
    }

    printf( "[+] Mapped KnownDlls\\ntdll.dll at address: 0x%p\n", baseAddress );


    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER )baseAddress;
    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS )( ( BYTE* )baseAddress + dosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION( ntHeaders );

    for ( DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++ ) {
        if ( strcmp( ( LPCSTR )pSectionHeader->Name, ".text" ) == 0 ) {
            LPVOID lpTextSecAddr = ( LPVOID )( ( PBYTE )baseAddress + pSectionHeader->PointerToRawData );
            SIZE_T textSecSize = pSectionHeader->SizeOfRawData;

            LPVOID lpNtdllTextSecAddr = ( LPVOID )( ( PBYTE )hNtdll + pSectionHeader->VirtualAddress );

            DWORD oldProtect;
            VirtualProtect( lpNtdllTextSecAddr, textSecSize, PAGE_EXECUTE_READWRITE, &oldProtect );

            memcpy( lpNtdllTextSecAddr, lpTextSecAddr, textSecSize );

            VirtualProtect( lpNtdllTextSecAddr, textSecSize, oldProtect, &oldProtect );
        }
    }

    printf( "[+] Unhooked ntdll.dll from KnownDlls cache\n" );

    NtUnmapViewOfSection( GetCurrentProcess(), baseAddress );
    CloseHandle( hSection );

    return 0;
}