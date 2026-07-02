CC = cl.exe
CFLAGS = /nologo /W4 /WX /O2

all: Threadless


Threadless: Threadless.c
	$(CC) $(CFLAGS) Threadless.c /FeThreadless.exe
	del *.obj
	
clean:
	del *.obj *.exe