EXTERN NtAllocateVirtualMemory_SSN:DWORD
EXTERN NtAllocateVirtualMemory_Addr:QWORD

.code

Sys_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, NtAllocateVirtualMemory_SSN
    jmp NtAllocateVirtualMemory_Addr
Sys_NtAllocateVirtualMemory ENDP

END