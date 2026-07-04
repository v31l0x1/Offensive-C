CC = cl.exe
CFLAGS = /nologo /W4 /O2

all: HalosGate

HalosGate: HalosGate.c
	$(CC) $(CFLAGS) HalosGate.c /FeHalosGate.exe
	del *.obj

clean:
	del HalosGate.exe