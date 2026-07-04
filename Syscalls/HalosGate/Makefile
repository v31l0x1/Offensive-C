CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: HalosGate

HalosGate: HalosGate.c	
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) HalosGate.c /FeHalosGate.exe /link syscall.obj
	del *.obj

clean:
	del *.exe *.obj