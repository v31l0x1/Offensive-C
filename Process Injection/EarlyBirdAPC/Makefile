CC = cl.exe
CFLAGS = /nologo /W4 /O2 

all: EarlyBird

EarlyBird: EarlyBird.c
	$(CC) $(CFLAGS) EarlyBird.c /Fe:EarlyBird.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb