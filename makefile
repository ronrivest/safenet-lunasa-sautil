#!/bin/true
# $Source: ossl_vob/sautil/makefile $ $Revision: 1.1 $
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

# Name of application:
APPNAME=sautil

# default target:
default all:
	sh configure.sh
	@echo

# clean target:
clean cleanall:
	rm -f a.out core 
	rm -f $(APPNAME) $(APPNAME).exe $(APPNAME).obj 
	@echo

#eof

