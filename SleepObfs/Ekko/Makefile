all: ekko

ekko: main.c
	x86_64-w64-mingw32-gcc -o ekko.exe main.c -mrdrnd
	rm -rf *.obj *.pdb

clean:
	rm -rf *.exe *.obj *.pdb