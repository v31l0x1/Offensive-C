CC = cl.exe
CFLAGS = /nologo /W4 /O2 

all: MockingJay

MockingJay: MockingJay.c
	$(CC) $(CFLAGS) MockingJay.c /FeMockingJay.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb