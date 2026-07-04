EXTERN NtAllocateVirtualMemory_SSN:DWORD

.code 

Sys_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, NtAllocateVirtualMemory_SSN
    syscall
    ret
Sys_NtAllocateVirtualMemory ENDP

END