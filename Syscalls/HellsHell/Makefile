CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: HellsHell

HellsHell: HellsHell.c
	ml64.exe /c /nologo syscall.asm
	$(CC) $(CFLAGS) HellsHell.c /FeHellsHell.exe /link syscall.obj
	del *.obj

clean:
	del *.exe *.obj *.pdb