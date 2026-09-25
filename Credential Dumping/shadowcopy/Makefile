all: shadowcopy

CXX = cl.exe
CXXFLAGS = /nologo /W4 /O2 ole32.lib vssapi.lib

shadowcopy: main.cc
	$(CXX) $(CXXFLAGS) main.cc /Fe$@.exe
	del *.obj *.pdb

clean:
	del *.exe *.obj *.pdb