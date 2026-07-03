all: VehExec

CC = cl.exe

VehExec: VehExec.c
	$(CC) /W4 /O2 VehExec.c /Fe$@.exe
	del *.obj *.pdb

Castexec: castexec.c
	$(CC) /W4 /O2 castexec.c /Fe$@.exe
	del *.obj *.pdb

AllocProtect: AllocProtect.c
	$(CC) /W4 /O2 AllocProtect.c /Fe$@.exe
	del *.obj *.pdb

CallbackExec: CallbackExec.c
	$(CC) /W4 /O2 CallbackExec.c /Fe$@.exe
	del *.obj *.pdb

FiberExec: FiberExec.c
	$(CC) /W4 /O2 FiberExec.c /Fe$@.exe
	del *.obj *.pdb

clean:
	del *.exe *.obj *.pdb