CC = cl.exe
CFLAGS = /nologo /W4 /O2 

all: ThreadHijack

ThreadHijack: Hijack.c
	$(CC) $(CFLAGS) Hijack.c /FeThreadHijack.exe
	del *.obj *.pdb

clean:
	del *.exe *.obj *.pdb