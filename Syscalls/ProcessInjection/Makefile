CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: ProcInject

ProcInject: ProcInject.c
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) ProcInject.c /FeProcInject.exe /link syscall.obj
	del *.obj

clean:	
	del *.exe *.obj *.pdb