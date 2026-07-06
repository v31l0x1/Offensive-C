CC = cl.exe 
CFLAGS = /nologo /W4 /O2

all: ImpersonateSystem

ImpersonateSystem: ImpersonateSystem.c
	$(CC) $(CFLAGS) ImpersonateSystem.c /FeImpersonateSystem.exe /link advapi32.lib
	del *.obj

clean:
	del *.exe *.obj