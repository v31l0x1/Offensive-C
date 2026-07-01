all: Inject


CC = cl.exe
CFLAGS = /W4 /O2


dll: DllMain.c
	$(CC) $(CFLAGS) DllMain.c /FeDllMain.dll /LD /link user32.lib

Inject: Inject.c
	$(CC) $(CFLAGS) Inject.c /FeInject.exe


clean:
	del *.exe *.dll *.obj *.pdb