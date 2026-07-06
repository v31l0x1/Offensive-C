#include <windows.h>
#include <stdio.h>

#pragma warning(disable: 4334)

typedef NTSTATUS( NTAPI* fnNtTraceEvent )(
    _In_opt_ HANDLE TraceHandle,
    _In_ ULONG Flags,
    _In_ ULONG FieldSize,
    _In_ PVOID Fields
    );
fnNtTraceEvent NtTraceEvent;

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

BOOL RemoveHwBp( HANDLE hThread, DWORD regIndex ) {

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if ( !GetThreadContext( hThread, &ctx ) ) {
        printf( "GetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    switch ( regIndex ) {
    case 0: ctx.Dr0 = 0; break;
    case 1: ctx.Dr1 = 0; break;
    case 2: ctx.Dr2 = 0; break;
    case 3: ctx.Dr3 = 0; break;
    default: return FALSE;
    }

    ctx.Dr7 &= ~( 1 << ( regIndex * 2 ) );

    if ( !SetThreadContext( hThread, &ctx ) ) {
        printf( "SetThreadContext failed: %d\n", GetLastError() );
        return FALSE;
    }

    return TRUE;
}


LONG WINAPI VectoredExceptionHandler( PEXCEPTION_POINTERS pExceptionInfo ) {

    if ( pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ) {

        if ( pExceptionInfo->ExceptionRecord->ExceptionAddress == ( PVOID )NtTraceEvent ) {

            // PVOID retAddr = *( PVOID* )pExceptionInfo->ContextRecord->Rsp;

            pExceptionInfo->ContextRecord->Rax = 0;
            pExceptionInfo->ContextRecord->Rip = *( DWORD64* )pExceptionInfo->ContextRecord->Rsp;
            pExceptionInfo->ContextRecord->Rsp += 8;

            pExceptionInfo->ContextRecord->Dr6 &= ~0xF;
            pExceptionInfo->ContextRecord->EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {

    HMODULE hNtdll = GetModuleHandleA( "ntdll.dll" );

    NtTraceEvent = ( fnNtTraceEvent )GetProcAddress( hNtdll, "NtTraceEvent" );

    printf( "[+] NtTraceEvent address: %p\n", NtTraceEvent );

    AddVectoredExceptionHandler( 1, VectoredExceptionHandler );

    SetHwBp( GetCurrentThread(), ( PVOID )NtTraceEvent, 0 );

    printf( "[+] Breakpoint set at 0x%p\n", NtTraceEvent );

    NtTraceEvent( NULL, 0, 0, NULL );

    system( "pause" );

    RemoveHwBp( GetCurrentThread(), 0 );

    return 0;
}