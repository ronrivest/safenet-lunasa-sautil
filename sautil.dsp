# Microsoft Developer Studio Project File - Name="sautil" - Package Owner=<4>
# Microsoft Developer Studio Generated Build File, Format Version 6.00
# ** DO NOT EDIT **

# TARGTYPE "Win32 (x86) External Target" 0x0106

CFG=SAUTIL - WIN32 RELEASE
!MESSAGE This is not a valid makefile. To build this project using NMAKE,
!MESSAGE use the Export Makefile command and run
!MESSAGE 
!MESSAGE NMAKE /f "sautil.mak".
!MESSAGE 
!MESSAGE You can specify a configuration when running NMAKE
!MESSAGE by defining the macro CFG on the command line. For example:
!MESSAGE 
!MESSAGE NMAKE /f "sautil.mak" CFG="SAUTIL - WIN32 RELEASE"
!MESSAGE 
!MESSAGE Possible choices for configuration are:
!MESSAGE 
!MESSAGE "sautil - Win32 Release" (based on "Win32 (x86) External Target")
!MESSAGE "sautil - Win32 Release X64" (based on "Win32 (x86) External Target")
!MESSAGE "sautil - Win32 Clean" (based on "Win32 (x86) External Target")
!MESSAGE 

# Begin Project
# PROP AllowPerConfigDependencies 0
# PROP Scc_ProjName ""
# PROP Scc_LocalPath ""

!IF  "$(CFG)" == "sautil - Win32 Release"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release"
# PROP BASE Intermediate_Dir "Release"
# PROP BASE Cmd_Line "NMAKE /f sautil.mak"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sautil.exe"
# PROP BASE Bsc_Name "sautil.bsc"
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release"
# PROP Intermediate_Dir "Release"
# PROP Cmd_Line "nmake /f "sautil.mak""
# PROP Rebuild_Opt "/a"
# PROP Target_File "sautil.exe"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sautil - Win32 Release X64"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "Release X64"
# PROP BASE Intermediate_Dir "Release X64"
# PROP BASE Cmd_Line "nmake /f "sautil.mak" default32"
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sautil.exe"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "Release X64"
# PROP Intermediate_Dir "Release X64"
# PROP Cmd_Line "nmake /f "sautil.mak" default64"
# PROP Rebuild_Opt "/a"
# PROP Target_File "sautil.exe"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ELSEIF  "$(CFG)" == "sautil - Win32 Clean"

# PROP BASE Use_MFC 0
# PROP BASE Use_Debug_Libraries 0
# PROP BASE Output_Dir "sautil___Win32_Clean"
# PROP BASE Intermediate_Dir "sautil___Win32_Clean"
# PROP BASE Cmd_Line "nmake /f "sautil.mak""
# PROP BASE Rebuild_Opt "/a"
# PROP BASE Target_File "sautil.exe"
# PROP BASE Bsc_Name ""
# PROP BASE Target_Dir ""
# PROP Use_MFC 0
# PROP Use_Debug_Libraries 0
# PROP Output_Dir "sautil___Win32_Clean"
# PROP Intermediate_Dir "sautil___Win32_Clean"
# PROP Cmd_Line "nmake /f "sautil.mak" clean"
# PROP Rebuild_Opt "/a"
# PROP Target_File "sautil.exe"
# PROP Bsc_Name ""
# PROP Target_Dir ""

!ENDIF 

# Begin Target

# Name "sautil - Win32 Release"
# Name "sautil - Win32 Release X64"
# Name "sautil - Win32 Clean"

!IF  "$(CFG)" == "sautil - Win32 Release"

!ELSEIF  "$(CFG)" == "sautil - Win32 Release X64"

!ELSEIF  "$(CFG)" == "sautil - Win32 Clean"

!ENDIF 

# Begin Group "Source Files"

# PROP Default_Filter "cpp;c;cxx;rc;def;r;odl;idl;hpj;bat"
# Begin Source File

SOURCE=.\sautil.c
# End Source File
# End Group
# Begin Group "Header Files"

# PROP Default_Filter "h;hpp;hxx;hm;inl"
# Begin Source File

SOURCE=".\e_lunaca3.h"
# End Source File
# Begin Source File

SOURCE=.\sautil.h
# End Source File
# End Group
# Begin Group "Resource Files"

# PROP Default_Filter "ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe"
# End Group
# Begin Source File

SOURCE=.\sautil.mak
# End Source File
# End Target
# End Project
