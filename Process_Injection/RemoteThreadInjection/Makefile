all: RemoteInject

CC = cl.exe
CFLAGS = /nologo /W4 /O2 /D_CRT_SECURE_NO_WARNINGS

RemoteInject: Inject.c
	$(CC) $(CFLAGS) Inject.c /FeRemoteInject.exe

clean:
	del *.exe *.obj *.pdb