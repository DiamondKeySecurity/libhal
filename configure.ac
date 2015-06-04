# -*- Autoconf -*-

# Copyright (c) 2015, SUNET
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Bare-minimum autoconf, with as little of the usual voodoo as
# possible.  This probably ought to be replaced by a ten-line Python
# script, some day when we have time to shave that yak.
#
# We deliberately avoid constructs like AC_PROG_CC because they're
# almost certain to guess wrong about the settings we want.
#
# If you don't understand why there are so many square brackets, put
# the keyboard down and back away slowly before somebody gets hurt.

AC_INIT([libcryptech], [0.1])

AC_ARG_VAR([FPGA_BUS],	[Bus architecture to use (currently must be "EIM" or "I2C")])
AC_ARG_VAR([CC],	[C compiler command])
AC_ARG_VAR([CFLAGS],	[C compiler flags])
AC_ARG_VAR([LDFLAGS],	[Linker flags])

AS_CASE($FPGA_BUS, [""],[FPGA_BUS=EIM], [EIM|I2C],[],
	[AC_MSG_ERROR([Invalid setting of FPGA_BUS, must be "EIM" or "I2C"])])
	
AS_CASE($CC,      [""],[CC="cc"],		  [])
AS_CASE($CFLAGS,  [""],[CFLAGS="-g -Wall -fPIC"], [])
AS_CASE($LDFLAGS, [""],[LDFLAGS="-g"],		  [])

AC_MSG_NOTICE([FPGA bus: $FPGA_BUS])
AC_MSG_NOTICE([C compiler: $CC])
AC_MSG_NOTICE([C compiler flags: $CFLAGS])
AC_MSG_NOTICE([Linker flags: $LDFLAGS])

AC_CONFIG_FILES([Makefile tests/Makefile])
AC_OUTPUT
