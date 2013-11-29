
# $Source: ossl_vob/sautil/sautil.mak $ $Revision: 1.1 $
################################################################################
#                                                                              #
#     Copyright (C) 2009 SafeNet, Inc. All rights reserved.                    #
#     See the attached file "SFNT_Legal.pdf" for the license terms and         #
#     conditions that govern the use of this software.                         #
#                                                                              #
#     Installing, copying, or otherwise using this software indicates your     #
#     acknowledgement that you have read the license and agree to be bound     #
#     by and comply with all of its terms and conditions.                      #
#                                                                              #
#     If you do not wish to accept these terms and conditions,                 #
#     DO NOT OPEN THE FILE OR USE THE SOFTWARE."                               #
#                                                                              #
################################################################################

SSL_PATH=c:\cygwin\usr\local\ssl

APPNAME=sautil

CL_OPTS32=-DMONOLITH /MT /Ox /O2 /Ob2 /W3 /WX /Gs0 /GF /Gy /nologo -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE 
CL_OPTS64=$(CL_OPTS32)

LIBBASE=kernel32.lib user32.lib gdi32.lib winspool.lib  comdlg32.lib advapi32.lib shell32.lib ole32.lib  oleaut32.lib uuid.lib odbc32.lib odbccp32.lib  wsock32.lib 
LIBFOO=bufferoverflowu.lib 
#LIBSTD=$(LIBBASE) $(LIBFOO)
LIBSTD=$(LIBBASE)

LIB32=/libpath:"$(SSL_PATH)\lib" ssleay32.lib  libeay32.lib  $(LIBSTD) 
LIB64=/libpath:"$(SSL_PATH)\lib" ssleay32.lib  libeay32.lib  $(LIBSTD) 

default:
	cl $(CL_OPTS32)  $(APPNAME).c  /D "OS_WIN32"  /I "$(SSL_PATH)\include" /link /out:$(APPNAME).exe $(APPNAME).obj $(LIB32)

default64:
	cl $(CL_OPTS64)  $(APPNAME).c  /D "OS_WIN64"  /D "OS_WIN32"  /I "$(SSL_PATH)\include" /link /machine:amd64 /out:$(APPNAME).exe $(APPNAME).obj $(LIB64)

clean:
	-del /q $(APPNAME).exe 
	-del /q $(APPNAME).obj 

