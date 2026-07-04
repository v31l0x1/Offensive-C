CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: ProcHollowing

ProcHollowing: ProcHollowing.c
	$(CC) $(CFLAGS) ProcHollowing.c /FeProcHollowing.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb