all: crypter_xor crypter_rc4 crypter_aes

crypter_xor: main.c
	cl.exe /W4 /O2 /DXOR_ENC main.c /Fecrypter_xor.exe

crypter_rc4: main.c
	cl.exe /W4 /O2 /DRC4_ENC main.c /Fecrypter_rc4.exe

crypter_aes: main.c
	cl.exe /W4 /O2 /DAES_ENC main.c /Fecrypter_aes.exe /link advapi32.lib 

crypter:
	cl.exe /W4 /O2 main.c 

clean:
	del *.obj *.exe *.pdb