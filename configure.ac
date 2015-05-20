# -*- Autoconf -*-

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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
