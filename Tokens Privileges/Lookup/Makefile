CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: Lookup

Lookup: main.c
	$(CC) $(CFLAGS) main.c /FeLookup.exe /link advapi32.lib
	del *.obj

clean:
	del *.exe *.obj