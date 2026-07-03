#include <windows.h>

__declspec( dllexport ) VOID FakeFunc( void ) {
    MessageBoxA( NULL, "FakeFunc called!", "DLL Injection", MB_OK | MB_ICONINFORMATION );
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {
    switch ( fdwReason ) {
    case DLL_PROCESS_ATTACH:
        MessageBoxA( NULL, "DLL Injected!", "DLL Injection", MB_OK | MB_ICONINFORMATION );
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}