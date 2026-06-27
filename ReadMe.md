## Build Commands

Open the **x64 Native Tools Command Prompt for VS 2022**.

```batch
REM Compile a C file to a 64-bit executable
cl /nologo /W3 /O2 program.c

REM Compile with no default libraries (small binary)
cl /nologo /GS- /MT program.c /link /NODEFAULTLIB:libcmt.lib kernel32.lib user32.lib

REM Compile with a custom entry point
cl /nologo program.c /link /ENTRY:Start

REM Compile a DLL
cl /nologo /LD program.c

REM Compile C++ with exceptions
cl /nologo /EHsc /W3 /O2 program.cpp

REM Compile with MASM assembly module
ml64 /c stub.asm
cl /nologo program.c stub.obj

REM Strip symbols and reduce size
cl /nologo /O1 /GS- /MT program.c /link /OPT:REF /OPT:ICF /MERGE:.rdata=.text
```

Common flags:

| Flag                 | Effect                                      |
| -------------------- | ------------------------------------------- |
| `/O2`                | Maximum optimization                        |
| `/O1`                | Optimize for size                           |
| `/GS-`               | Disable buffer security checks              |
| `/MT`                | Static CRT (no dependency on vcruntime DLL) |
| `/MD`                | Dynamic CRT                                 |
| `/LD`                | Build a DLL                                 |
| `/EHsc`              | C++ exception handling                      |
| `/W3`                | Warning level 3                             |
| `/nologo`            | Suppress compiler banner                    |
| `/ENTRY:Name`        | Custom entry point                          |
| `/SUBSYSTEM:WINDOWS` | No console window                           |
| `/SUBSYSTEM:CONSOLE` | Console window (default)                    |

## Useful Headers and Libraries

| Header       | Purpose                               | Library                                  |
| ------------ | ------------------------------------- | ---------------------------------------- |
| `windows.h`  | Core Win32                            | `kernel32.lib`, `user32.lib`             |
| `winternl.h` | NT structures                         | none (functions need dynamic resolution) |
| `tlhelp32.h` | Toolhelp snapshots                    | `kernel32.lib`                           |
| `psapi.h`    | `EnumProcesses`, `EnumProcessModules` | `psapi.lib`                              |
| `tlhelp32.h` | `Process32First` / `Module32First`    | `kernel32.lib`                           |
| `bcrypt.h`   | AES, SHA via CNG                      | `bcrypt.lib`                             |
| `wincrypt.h` | Legacy CryptoAPI                      | `crypt32.lib`                            |
| `winhttp.h`  | HTTP/HTTPS                            | `winhttp.lib`                            |
| `wininet.h`  | HTTP/FTP (legacy)                     | `wininet.lib`                            |
| `winsock2.h` | Sockets                               | `ws2_32.lib`                             |
| `dbghelp.h`  | Symbol resolution                     | `dbghelp.lib`                            |
| `intrin.h`   | Compiler intrinsics                   | none                                     |

## Common Pitfalls

| Symptom                                         | First Step                                                              |
| ----------------------------------------------- | ----------------------------------------------------------------------- |
| Compiler complains about strcpy/sprintf         | Add `#define _CRT_SECURE_NO_WARNINGS` at top                            |
| unresolved external symbol \_DllMainCRTStartup  | Add `/ENTRY:DllMain` or use `/MT`                                       |
| Binary much larger than expected                | Switch to `/MT` and add `/OPT:REF /OPT:ICF`                             |
| `GetLastError` returns 5 (access denied)        | Need SeDebugPrivilege or higher integrity                               |
| `GetLastError` returns 6 (invalid handle)       | Probably called `CloseHandle` twice or used a NULL handle               |
| Shellcode crashes immediately                   | Page protection is not `PAGE_EXECUTE_*`, or calling convention mismatch |
| `VirtualAllocEx` returns NULL on remote process | Process is protected (PPL) or wrong access mask                         |
| Syscall stub returns 0xC0000005                 | Wrong SSN for current Windows build, or NX page                         |
| HBP fires but never resumes                     | Forgot to clear `EFlags.RF` or didn't single-step properly              |
