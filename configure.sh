#!/bin/sh
# $Source: ossl_vob/sautil/configure.sh $ $Revision: 1.1 $
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
#
# PURPOSE:
#
#   build application within unix environment
#
#
# PRE-REQUISITES:
#
# - openssl toolkit installed at "/usr/local/ssl" (headers and libcrypto)
# - cryptoki library configured via "$ChrystokiConfigurationPath/Chrystoki.conf" (UNIX only)
#   - or, cryptoki library configured via "%ChrystokiConfigurationPath%\crystoki.ini" (Windows only)
#
#
# NOTES:
#
# - source code can be compiled using C or C++ compiler (if not true then report this as a bug)
#

# Name of application:
APPNAME=sautil

# Operating system:
UNAMES=`uname -s`
UNAMEM=`uname -m`
UNAMEP=`uname -p`
UNAMEO=`uname -o 2> /dev/null`
echo "System... $UNAMES"

# C/C++ Compiler:
echo "uname -a... `uname -a`"
echo "which cc... `which cc`"
echo "which gcc... `which gcc`"
echo "which cl... `which cl`"
echo "which xlc... `which xlc`"
echo "which CC... `which CC`"
echo "which g++... `which g++`"
echo "which aCC... `which aCC`"

# Compiler:
CC="cc"
CFLAGS_64="-m64"
CFLAGS_32="-m32"
LDFLAGS_END="-ldl"

# try_compile:
try_compile() {
  if [ ! "$CC" = "" ]; then
    echo "CC=$CC"
    echo "CFLAGS_64=$CFLAGS_64"
    echo "CFLAGS_32=$CFLAGS_32"
    echo "LDFLAGS_END=$LDFLAGS_END"
    if [ ! -x $APPNAME ]; then
      $CC -o $APPNAME $APPNAME.c  -DOS_UNIX  -I/usr/local/ssl/include  -L/usr/local/ssl/lib -lssl -lcrypto $LDFLAGS_END 
    fi
    if [ ! -x $APPNAME ]; then
      $CC $CFLAGS_64 -o $APPNAME $APPNAME.c  -DOS_UNIX  -I/usr/local/ssl/include  -L/usr/local/ssl/lib -lssl -lcrypto $LDFLAGS_END 
    fi
    if [ ! -x $APPNAME ]; then
      $CC $CFLAGS_32 -o $APPNAME $APPNAME.c  -DOS_UNIX  -I/usr/local/ssl/include  -L/usr/local/ssl/lib -lssl -lcrypto $LDFLAGS_END 
    fi
    if [ -x $APPNAME ]; then
      file $APPNAME 
      echo "Installing to /usr/local/$APPNAME/bin/$APPNAME" 
      mkdir -p /usr/local/$APPNAME/bin 
      cp -f $APPNAME /usr/local/$APPNAME/bin/$APPNAME 
      if [ "$?" = "0" ]; then
        echo "Success."
        exit 0
      fi
    fi
  fi
}


# try_compile_win32:
try_compile_win32() {
  if [ "" = "" ]; then
    if [ "$SSL_PATH" = "" ]; then
      SSL_PATH="c:\cygwin\usr\local\ssl"
    fi
    CL_OPTS="-DMONOLITH /MT /Ox /O2 /Ob2 /W3 /WX /Gs0 /GF /Gy /nologo -DWIN32_LEAN_AND_MEAN -DL_ENDIAN -DDSO_WIN32 -D_CRT_SECURE_NO_DEPRECATE -D_CRT_NONSTDC_NO_DEPRECATE"
    LDFLAGS_END="kernel32.lib user32.lib gdi32.lib winspool.lib  comdlg32.lib advapi32.lib shell32.lib ole32.lib  oleaut32.lib uuid.lib odbc32.lib odbccp32.lib  wsock32.lib  ssleay32.lib  libeay32.lib"
    LDFLAGS_FOO="bufferoverflowu.lib"
    # try 64-bit before 32-bit on windows:
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS  $APPNAME.c  /D "OS_WIN32" /D "OS_WIN64"  /I "$SSL_PATH\include" /link /machine:amd64 /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_END 
    fi
    if [ ! -x $APPNAME.exe ]; then
      cl $CL_OPTS  $APPNAME.c  /D "OS_WIN32"  /I "$SSL_PATH\include" /link /out:$APPNAME.exe $APPNAME.obj /libpath:"$SSL_PATH\lib" $LDFLAGS_END 
    fi
    if [ -x $APPNAME.exe ]; then
      file $APPNAME.exe 
      echo "Installing to /usr/local/$APPNAME/bin/$APPNAME.exe" 
      mkdir -p /usr/local/$APPNAME/bin 
      cp -f $APPNAME.exe /usr/local/$APPNAME/bin/$APPNAME.exe 
      if [ "$?" = "0" ]; then
        echo "Success."
        exit 0
      fi
    fi
  fi
}


# SunOS:
if [ "$UNAMES" = "SunOS" ]; then
  CC="cc"
  LDFLAGS_END="-lsocket -ldl"
  if [ "$UNAMEP" = "sparc" ]; then
    CFLAGS_64="-xarch=v9"
    #CFLAGS_64="-m64"
  else
    CFLAGS_64="-xarch=amd64"
    #CFLAGS_64="-m64"
  fi
  try_compile
  exit 1
fi


# AIX:
if [ "$UNAMES" = "AIX" ]; then
  CC="cc -qcpluscmt -O2 -qstrict -qmaxmem=16384 -qtbtable=none"
  LDFLAGS_END=
  CFLAGS_64="-q64"
  try_compile
  exit 1
fi


# HP-UX:
if [ "$UNAMES" = "HP-UX" ]; then
  LDFLAGS_END="-ldl"
  if [ "$UNAMEM" = "ia64" ]; then
    CC="cc -D__NO_PA_HDRS"
    CFLAGS_64="-Ae +DD64 +DSitanium2 +DAportable"
  else
    CC="cc -DPARISC -D__NO_EM_HDRS -D__hp9000s800"
    CFLAGS_64="-Ae +DD64 +DS2.0 +DAportable"
  fi
  try_compile
  exit 1
fi


# Cygwin:
if [ "$UNAMEO" = "Cygwin" ]; then
  CC="cl"
  try_compile_win32
  exit 1
fi


# Backstop:
if [ "Backstop" = "Backstop" ]; then
  try_compile
fi

exit 1


#eof

