all: NoImports


NoImports:
	cl.exe /W4 /O2 NoImports.c
	del *.obj *.pdb

Resolver: 
	cl.exe /W4 /O2 Resolver.c
	del *.obj *.pdb

GetProcAddr:
	cl.exe /W4 /O2 GetProcAddress.c
	del *.obj *.pdb

GetModuleHandle:
	cl.exe /W4 /O2 GetModuleHandle.c
	del *.obj *.pdb

clean:
	del *.exe *.obj *.pdb