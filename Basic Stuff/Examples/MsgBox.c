#include <windows.h>
#include <stdio.h>

typedef int ( WINAPI* MESSAGEBOX )(
    HWND    hWnd,
    LPCTSTR lpText,
    LPCTSTR lpCaption,
    UINT    uType
    );


int main() {
    HMODULE hUser32 = LoadLibraryA( "user32.dll" );
    if ( !hUser32 ) {
        fprintf( stderr, "[-] LoadLibraryA failed: %lu\n", GetLastError() );
        return 1;
    }
    MESSAGEBOX pMessageBox = ( MESSAGEBOX )GetProcAddress( hUser32, "MessageBoxA" );
    if ( !pMessageBox ) {
        fprintf( stderr, "[-] GetProcAddress failed: %lu\n", GetLastError() );
        FreeLibrary( hUser32 );
        return 1;
    }
    pMessageBox( NULL, "Hello From PE!", "INFO", MB_OK | MB_ICONINFORMATION );
    return 0;
}