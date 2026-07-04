CC = cl.exe
CFLAGS = /nologo /W4 /O2 

all: ModuleStomp

ModuleStomp: ModuleStomp.c
	$(CC) $(CFLAGS) ModuleStomp.c /FeModuleStomp.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb