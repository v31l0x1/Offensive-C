CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: APCInject

APCInject: ApcInject.c
	$(CC) $(CFLAGS) ApcInject.c /FeAPCInject.exe
	del *.obj *.pdb

clean:
	del *.exe *.obj *.pdb
