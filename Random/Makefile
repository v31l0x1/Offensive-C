all:

envinfo: envinfo.c
	cl.exe /W4 /MT /OS /GS- /Zl envinfo.c /link /SUBSYSTEM:CONSOLE /ENTRY:main kernel32.lib advapi32.lib

xorenc: xorenc.c
	cl.exe /W4 /O2 xorenc.c

flagsdump: flagsdump.c
	cl.exe /W4 /O2 flagsdump.c

dispatch: dispatch.c
	cl.exe /W4 /O2 dispatch.c /link User32.lib

hexdump: hexdump.c
	cl.exe /W4 /O2 hexdump.c

strings: strings.c
	cl.exe /W4 /OS strings.c

bytewalk: bytewalk.c
	cl.exe /W4 /O2 bytewalk.c

procwalk: procwalk.c
	cl.exe /W4 /O2 procwalk.c

memwalk: memwalk.c
	cl.exe /W4 /O2 memwalk.c

rwxfinder: rwxfinder.c
	cl.exe /W4 /O2 rwxfinder.c

hostrecon: hostrecon.c
	cl.exe /W4 /O2 hostrecon.c /link advapi32.lib iphlpapi.lib ws2_32.lib

resolver: resolver.c
	cl.exe /W4 /O2 resolver.c

peparser: peparser.c
	cl.exe /W4 /O2 peparser.c

filerecon: filerecon.c
	cl.exe /W4 /O2 filerecon.c

regenum: regenum.c
	cl.exe /W4 /O2 regenum.c /link advapi32.lib

procop: procop.c
	cl.exe /W4 /O2 procop.c

threadsplay: threadsplay.c
	cl.exe /W4 /O2 threadsplay.c

tokenrecon: tokenrecon.c
	cl.exe /W4 /O2 tokenrecon.c /link advapi32.lib

tcpscan: tcpscan.c
	cl.exe /W4 /O2 tcpscan.c /link ws2_32.lib

clean:
	del *.exe *.obj *.pdb