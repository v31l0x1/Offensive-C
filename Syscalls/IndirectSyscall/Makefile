CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: IndirectSyscall

IndirectSyscall: IndSyscall.c
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) IndSyscall.c /FeIndSyscall.exe /link syscall.obj
	del *.obj

clean:
	del *.exe *.obj *.pdb