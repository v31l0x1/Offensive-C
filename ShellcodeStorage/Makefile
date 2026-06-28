all: sstore

cert:
	del *.pvk *.cer *.pfx
	makecert -r -pe -n "CN=Microsoft Root Certificate Authority 2010,O=Microsoft Corporation,L=Redmond,S=Washington,C=US" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv CA.pvk CA.cer
	makecert -pe -n "CN=Microsoft Root Certificate Authority 2010,O=Microsoft Corporation,L=Redmond,S=Washington,C=US" -a sha256 -cy end -sky signature -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.24,1.3.6.1.4.1.311.10.3.6 -ic CA.cer -iv CA.pvk -sv SPC.pvk SPC.cer
	pvk2pfx -pvk SPC.pvk -spc SPC.cer -pfx SPC.pfx
	@echo Certificate generation complete.

sstore: main.c
	rc /nologo resource.rc
	cl.exe /nologo /W4 /O2 main.c resource.res
	signtool sign /v /fd SHA256 /f SPC.pfx main.exe
	signtool timestamp /tr http://timestamp.digicert.com /td SHA256 main.exe
# 	signtool verify /v /pa main.exe

clean: 
	del *.obj *.exe *.pdb *.res *.pvk *.cer *.pfx