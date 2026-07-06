CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: UnHookFromSuspendProcess

UnHookFromSuspendProcess: UnHook.c
	$(CC) $(CFLAGS) UnHook.c /FeUnHook.exe
	del *.obj

clean:
	del *.exe *.obj