all: debug release

debug: hello.c hello.cc
	cl.exe /W4 /Zi hello.c /nologo /Fehello_c.exe
	cl.exe /W4 /Zi /EHsc hello.cc /nologo /Fehello_cpp.exe

release: hello.c hello.cc
	cl.exe /W4 /Zi /O2 hello.c /nologo /Fehello_c.exe
	cl.exe /W4 /Zi /EHsc /O2 hello.cc /nologo /Fehello_cpp.exe

clean:
	del *.obj *.exe *ilk *.pdb