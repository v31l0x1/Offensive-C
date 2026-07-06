CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: EnablePrivilege

EnablePrivilege: main.c
	$(CC) $(CFLAGS) main.c /FeEnablePrivilege.exe /link advapi32.lib
	del *.obj

clean:
	del *.exe *.obj