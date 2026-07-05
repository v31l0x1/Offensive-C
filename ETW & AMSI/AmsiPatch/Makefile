CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: AmsiPatch

AmsiPatch: AmsiPatch.c
	$(CC) $(CFLAGS) /FeAmsiPatch.exe AmsiPatch.c

clean:
	del *.exe *.obj