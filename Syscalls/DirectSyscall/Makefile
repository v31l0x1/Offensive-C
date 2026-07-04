CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: syscalls

syscalls: syscalls.c
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) syscalls.c /Fesyscalls.exe /link syscall.obj
	del *.obj

clean:
	del *.obj *.exe