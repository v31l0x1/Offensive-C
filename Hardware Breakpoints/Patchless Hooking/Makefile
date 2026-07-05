CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: Hook

Hook: main.c
	$(CC) $(CFLAGS) main.c /FeHook.exe

clean:
	del *.exe *.obj