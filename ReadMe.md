```
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
