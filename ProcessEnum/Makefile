all: ProcEnum

CC = cl.exe
CFLAGS = /W4 /O2

ProcEnum: ProcEnum.c
	$(CC) $(CFLAGS) ProcEnum.c /FeProcEnum.exe

clean:
	del *.exe *.obj *.pdb