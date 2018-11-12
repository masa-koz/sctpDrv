PEXPORTS=pexports
DLLTOOL=dlltool
DLLTOOL_FLAGS=-k

all: \
	libsctpsp.a

libsctpsp.a: libsctpsp.def
	$(DLLTOOL) $(DLLTOOL_FLAGS) --output-lib $@ --def $*.def

libsctpsp.def:
	$(PEXPORTS) -h ..\inc\ws2sctp.h ..\..\wix\bin\xp32\sctpsp.dll > libsctpsp.def

clean:
	del *.a *.def
