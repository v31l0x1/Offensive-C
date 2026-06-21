#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

// cl.exe /W4 data.c
// C:\Users\admin\Offensive-C\Memory>.\data.exe
// code (main): 00007FF79D171000
// .data      : 00007FF79D191000
// .rdata     : 00007FF79D186330
// .bss       : 00007FF79D191BA0
// stack      : 000000D0EEF1FA30
// heap       : 000002B89FDFBFA0

int g_initialized = 0xAA;
const int g_readonly = 0xBB;
static int g_uninit;


char* state_name( DWORD state ) {
    switch ( state )
    {
    case MEM_COMMIT: return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE: return "MEM_FREE";
    default:
        return "Other";
    }
}

char* type_protect( DWORD state ) {
    switch ( state )
    {
    case PAGE_NOACCESS: return "PAGE_NOACCESS";
    case PAGE_READONLY: return "PAGE_READONLY";
    case PAGE_READWRITE: return "PAGE_READWRITE";
    case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
    case PAGE_EXECUTE: return "PAGE_EXECUTE";
    case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
    case PAGE_GUARD: return "PAGE_GUARD";
    case PAGE_NOCACHE: return "PAGE_NOCACHE";
    case PAGE_WRITECOMBINE: return "PAGE_WRITECOMBINE";
    default:
        return "Other";
    }
}

char* type_name( DWORD type ) {
    switch ( type )
    {
    case MEM_IMAGE:
        return "MEM_IMAGE";
    case MEM_MAPPED:
        return "MEM_MAPPED";
    case MEM_PRIVATE:
        return "MEM_PRIVATE";
    case 0:
        return "-";
    default:
        return "Other";
    }
}

int main( void ) {

    int stack_var = 0xCC;
    int* heap_var = ( int* )malloc( sizeof( int ) );

    printf( "code (main): %p\n", ( void* )&main );
    printf( ".data      : %p\n", ( void* )&g_initialized );
    printf( ".rdata     : %p\n", ( void* )&g_readonly );
    printf( ".bss       : %p\n", ( void* )&g_uninit );
    printf( "stack      : %p\n", ( void* )&stack_var );
    printf( "heap       : %p\n", ( void* )heap_var );

    printf( "\n" );
    LPVOID addr = NULL;
    MEMORY_BASIC_INFORMATION mbi;

    while ( VirtualQuery( addr, &mbi, sizeof( mbi ) ) ) {
        printf( "BaseAddress: %p, RegionSize: 0x%016llX, State: %s, Protection: %s, Type: %s\n",
            mbi.BaseAddress,
            mbi.RegionSize,
            state_name( mbi.State ),
            type_protect( mbi.Protect ),
            type_name( mbi.Type ) );

        addr = ( LPVOID )( ( SIZE_T )mbi.BaseAddress + mbi.RegionSize );
    }

}