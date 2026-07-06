CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: UnHookFromDisk

UnHookFromDisk: UnHook.c
	$(CC) $(CFLAGS) UnHook.c /FeUnHookFromDisk.exe
	del *.obj

clean:
	del *.exe *.obj