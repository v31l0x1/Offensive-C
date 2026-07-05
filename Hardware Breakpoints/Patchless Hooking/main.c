#include <windows.h>
#include <stdio.h>

#pragma warning( disable : 4334 )

typedef int ( WINAPI* fnMessageBoxA )( HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType );

fnMessageBoxA pMessageBoxA;

BOOL SetHwBp( HANDLE hThread, PVOID pAddress, DWORD regIndex ) {

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext( hThread, &ctx ) ) {
        return FALSE;
    }

    switch ( regIndex ) {
    case 0: ctx.Dr0 = ( DWORD_PTR )pAddress; break;
    case 1: ctx.Dr1 = ( DWORD_PTR )pAddress; break;
    case 2: ctx.Dr2 = ( DWORD_PTR )pAddress; break;
    case 3: ctx.Dr3 = ( DWORD_PTR )pAddress; break;
    default: return FALSE;
    }

    ctx.Dr7 |= ( 1 << ( regIndex * 2 ) );
    ctx.Dr7 &= ~( 1 << ( 16 + regIndex * 4 ) );
    ctx.Dr7 &= ~( 1 << ( 17 + regIndex * 4 ) );

    if ( !SetThreadContext( hThread, &ctx ) ) {
        return FALSE;
    }
    return TRUE;
}

LONG WINAPI VectoredHandler( PEXCEPTION_POINTERS pExceptionInfo ) {

    if ( pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {

        if ( pExceptionInfo->ExceptionRecord->ExceptionAddress == ( PVOID )pMessageBoxA ) {
            printf( "Hardware breakpoint hit at MessageBoxA!\n" );

            printf( "RCX: 0x%llx\n", pExceptionInfo->ContextRecord->Rcx );
            printf( "RDX: 0x%llx\n", pExceptionInfo->ContextRecord->Rdx );
            printf( "R8: 0x%llx\n", pExceptionInfo->ContextRecord->R8 );
            printf( "R9: 0x%llx\n", pExceptionInfo->ContextRecord->R9 );

            PVOID pReturnAddress = ( PVOID )pExceptionInfo->ContextRecord->Rsp;
            printf( "Return Address: 0x%p\n", pReturnAddress );

            pExceptionInfo->ContextRecord->Rdx = ( DWORD_PTR )"Hooked!";

            pExceptionInfo->ContextRecord->EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main( void ) {

    HMODULE hUser32 = LoadLibraryA( "user32.dll" );

    pMessageBoxA = ( fnMessageBoxA )GetProcAddress( hUser32, "MessageBoxA" );

    if ( !pMessageBoxA ) {
        printf( "Failed to get MessageBoxA address\n" );
        return 1;
    }

    AddVectoredExceptionHandler( 1, VectoredHandler );
    SetHwBp( GetCurrentThread(), ( PVOID )pMessageBoxA, 0 );

    pMessageBoxA( NULL, "Hello, World!", "Message", MB_OK );

}