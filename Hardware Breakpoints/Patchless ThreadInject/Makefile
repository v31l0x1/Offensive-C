CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: PatchlessThreadInject

PatchlessThreadInject: ThreadInject.c
	$(CC) $(CFLAGS) ThreadInject.c /FePatchlessThreadInject.exe
	del *.obj

clean:
	del *.exe *.obj