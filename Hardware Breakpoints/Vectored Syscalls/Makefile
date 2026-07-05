CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: VectoredSyscalls

VectoredSyscalls: main.c
	$(CC) $(CFLAGS) main.c /FeVectoredSyscalls.exe
	del *.obj

clean:
	del *.exe *.obj