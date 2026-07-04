.code 

Sys_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 18h
    syscall
    ret
Sys_NtAllocateVirtualMemory ENDP

Sys_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, 50h
    syscall
    ret
Sys_NtProtectVirtualMemory ENDP

Sys_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, 3Ah
    syscall
    ret
Sys_NtWriteVirtualMemory ENDP

END