CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: PatchlessETWBypass

PatchlessETWBypass: Patchless.c
	$(CC) $(CFLAGS) Patchless.c /FePatchlessETWBypass.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb