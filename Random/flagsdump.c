#include <stdio.h>
#include <stdlib.h>
#include <windows.h>


typedef struct {
    DWORD bit;
    const char* name;
} FlagEntry;

static const FlagEntry kAccess[] = {
    { GENERIC_READ,   "GENERIC_READ"    },
    { GENERIC_WRITE,  "GENERIC_WRITE"   },
    { GENERIC_EXECUTE,"GENERIC_EXECUTE" },
    { GENERIC_ALL,    "GENERIC_ALL"     },
    { DELETE,         "DELETE"          },
    { READ_CONTROL,   "READ_CONTROL"    },
    { WRITE_DAC,      "WRITE_DAC"       },
    { WRITE_OWNER,    "WRITE_OWNER"     },
    { SYNCHRONIZE,    "SYNCHRONIZE"     },
};

int main( int argc, char* argv[] ) {
    if ( argc < 2 ) {
        fprintf( stderr, "Usage: %s <hex_flags>\n", argv[ 0 ] );
        return 1;
    }

    DWORD flags = ( DWORD )strtoul( argv[ 1 ], NULL, 16 );
    printf( "Flags: 0x%08X\n", flags );

    size_t n = sizeof( kAccess ) / sizeof( kAccess[ 0 ] );

    int bitCount = 0;

    for ( size_t i = 0; i < n; i++ ) {
        int set = ( flags & kAccess[ i ].bit ) == kAccess[ i ].bit;
        printf( "%-18s [%c]\n", kAccess[ i ].name, set ? 'X' : ' ' );
        if ( set ) {
            bitCount++;
        }
    }

    printf( "Total set bits: %d\n", bitCount );
    return 0;
}