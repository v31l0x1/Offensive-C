CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: HellsGate

HellsGate: HellsGate.c
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) HellsGate.c /FeHellsGate.exe /link syscall.obj
	del *.obj

clean:
	del *.exe