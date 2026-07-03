CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: stomp

stomp: stomp.c
	$(CC) $(CFLAGS) stomp.c /Festomp.exe
	del *.obj

clean:
	del *.exe *.obj *.pdb