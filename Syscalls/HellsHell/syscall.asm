;EXTERN NtAllocateVirtualMemory_SSN:DWORD
;EXTERN NtAllocateVirtualMemory_Addr:QWORD

_DATA$00 SEGMENT PAGE 'DATA'


PUBLIC NtAllocateVirtualMemory_SSN
PUBLIC NtAllocateVirtualMemory_Addr

NtAllocateVirtualMemory_SSN DWORD 0
NtAllocateVirtualMemory_Addr QWORD 0

_DATA$00 ENDS


.code

Sys_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [NtAllocateVirtualMemory_SSN]
    jmp qword ptr [NtAllocateVirtualMemory_Addr]
Sys_NtAllocateVirtualMemory ENDP

END