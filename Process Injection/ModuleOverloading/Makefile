CC = cl.exe
CFLAGS = /nologo /W4 /O2 

all: ModuleOverload

ModuleOverload: ModuleOverload.c
	$(CC) $(CFLAGS) ModuleOverload.c /FeModuleOverload.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb