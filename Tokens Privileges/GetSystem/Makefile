CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: GetSystem

GetSystem: GetSystem.c
	$(CC) $(CFLAGS) GetSystem.c /FeGetSystem /link advapi32.lib
	del *.obj

clean:
	del *.exe *.obj
