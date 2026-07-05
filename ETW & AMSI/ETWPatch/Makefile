CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: ETWPatch

ETWPatch: ETWPatch.c
	$(CC) $(CFLAGS) ETWPatch.c /FeETWPatch.exe
	del *.obj

clean:
	del *.exe *.obj