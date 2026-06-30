all: http_stager

http_stager:
	cl.exe /W4 /O2 http_stager.c

reg_stager:
	cl.exe /W4 /O2 reg_stager.c /link advapi32.lib 

clean:
	del *.exe *.obj *.pdb