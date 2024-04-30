CC=cl.exe
CFGFLAG=/guard:cf
XFGFLAG=/guard:xfg
CFLAGS=/W4 /nologo /Zi /EHsc
LINKFLAGS=/link mincore.lib

# all: wcfg_icall.exe no_wcfg_icall.exe wcfg_setjmp.exe wcfg_suppressed_export.dll wcfg_supp.exe xfg_icall.exe xfg_bypass.exe coop.exe coop_wcfg.exe coop_xfg.exe

all: wcfg_icall.exe xfg_icall.exe

wcfg_icall.exe: wcfg_icall.c
	 $(CC) $(CFLAGS) $(CFGFLAG) /Fe$@  $** $(LINKFLAGS) $(CFGFLAG)

# wcfg_setjmp.exe: setjmp_example.c
# 	 $(CC) $(CFLAGS) $(CFGFLAG) /Fe$@  $** $(LINKFLAGS) $(CFGFLAG)

xfg_icall.exe: wcfg_icall.c
	 $(CC) $(CFLAGS) $(XFGFLAG) /Fe$@  $** $(LINKFLAGS) $(XFGFLAG)

# no_wcfg_icall.exe: wcfg_icall.c
# 	 $(CC) $(CFLAGS) /Fe$@  $** $(LINKFLAGS) $(CFGFLAG)

# wcfg_suppressed_export.dll: wcfg_suppressed_export.cpp
# 	 $(CC) /O2 /W4 /nologo /Fe$@ $** $(LINKFLAGS) /DLL

# wcfg_supp.exe: wcfg_supp.cpp
# 	$(CC) $(CFLAGS) $(CFGFLAG) /Fe$@ /I . $** $(LINKFLAGs) $(CFGFLAG) /link wcfg_suppressed_export.lib

# xfg_bypass.exe: xfg_bypass.cpp
# 	$(CC) $(CFLAGS) $(XFGFLAG) /Fe$@ $** $(LINKFLAGS) $(XFGFLAG)

# coop.exe: coop.cpp
# 	$(CC) $(CFLAGS) /Fe$@ $** $(LINKFLAGS)

# coop_wcfg.exe: coop.cpp
# 	$(CC) $(CFLAGS) $(CFGFLAG) /Fe$@ $** $(LINKFLAGS) $(CFGFLAG)

# coop_xfg.exe: coop.cpp
# 	$(CC) $(CFLAGS) $(XFGFLAG) /Fe$@ $** $(LINKFLAGS) $(XFGFLAG)

clean:
	 del *.ilk *.pdb *.obj *.exe *.exp *.dll *.lib
