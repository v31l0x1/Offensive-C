.data

PUBLIC NtQuerySystemInformation_SSN
PUBLIC NtAllocateVirtualMemory_SSN
PUBLIC NtProtectVirtualMemory_SSN
PUBLIC NtWriteVirtualMemory_SSN
PUBLIC NtCreateThreadEx_SSN

PUBLIC NtAllocateVirtualMemory_Addr
PUBLIC NtProtectVirtualMemory_Addr
PUBLIC NtWriteVirtualMemory_Addr
PUBLIC NtCreateThreadEx_Addr
PUBLIC NtQuerySystemInformation_Addr

NtAllocateVirtualMemory_SSN DWORD 0
NtProtectVirtualMemory_SSN DWORD 0
NtWriteVirtualMemory_SSN DWORD 0
NtCreateThreadEx_SSN DWORD 0
NtQuerySystemInformation_SSN DWORD 0

NtAllocateVirtualMemory_Addr QWORD 0
NtProtectVirtualMemory_Addr QWORD 0
NtWriteVirtualMemory_Addr QWORD 0
NtCreateThreadEx_Addr QWORD 0
NtQuerySystemInformation_Addr QWORD 0


.code 

Sys_NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [NtAllocateVirtualMemory_SSN]
    jmp qword ptr [NtAllocateVirtualMemory_Addr]
Sys_NtAllocateVirtualMemory ENDP

Sys_NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [NtProtectVirtualMemory_SSN]
    jmp qword ptr [NtProtectVirtualMemory_Addr]
Sys_NtProtectVirtualMemory ENDP

Sys_NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [NtWriteVirtualMemory_SSN]
    jmp qword ptr [NtWriteVirtualMemory_Addr]
Sys_NtWriteVirtualMemory ENDP

Sys_NtCreateThreadEx PROC
    mov r10, rcx
    mov eax, dword ptr [NtCreateThreadEx_SSN]
    jmp qword ptr [NtCreateThreadEx_Addr]
Sys_NtCreateThreadEx ENDP

Sys_NtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, dword ptr [NtQuerySystemInformation_SSN]
    jmp qword ptr [NtQuerySystemInformation_Addr]
Sys_NtQuerySystemInformation ENDP

END

