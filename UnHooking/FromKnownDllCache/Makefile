CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: UnHookFromCache

UnHookFromCache: UnHook.c
	$(CC) $(CFLAGS) UnHook.c /FeUnHookFromCache.exe
	del *.obj

clean:
	del *.exe *.obj