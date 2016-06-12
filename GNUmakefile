# Copyright (c) 2015-2016, NORDUnet A/S
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
# - Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# - Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in the
#   documentation and/or other materials provided with the distribution.
#
# - Neither the name of the NORDUnet nor the names of its contributors may
#   be used to endorse or promote products derived from this software
#   without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Number of static hash and HMAC state blocks to allocate.
# Numbers pulled out of a hat, just testing.

STATIC_HASH_STATE_BLOCKS = 10
STATIC_HMAC_STATE_BLOCKS = 4
STATIC_PKEY_STATE_BLOCKS = 6

INC		= hal.h hal_internal.h
LIB		= libhal.a

# Error checking on known control options, some of which allow the user entirely too much rope.

USAGE := "usage: ${MAKE} [IO_BUS=eim|i2c|fmc] [RPC_CLIENT=none|local|remote|mixed] [RPC_SERVER=no|yes] [KS=volatile|mmap|flash] [RPC_TRANSPORT=none|loopback|serial|daemon] [MODEXP_CORE=no|yes]"

IO_BUS		?= eim
KS		?= mmap
RPC_CLIENT	?= none
RPC_SERVER	?= $(if $(filter local,${RPC_CLIENT}),yes,no)
RPC_TRANSPORT	?= daemon
MODEXP_CORE	?= no

ifeq (,$(and \
	$(filter	none eim i2c fmc		,${IO_BUS}),\
	$(filter	none local remote mixed		,${RPC_CLIENT}),\
	$(filter	no yes				,${RPC_SERVER}),\
	$(filter	volatile mmap flash		,${KS}),\
	$(filter	none loopback serial daemon	,${RPC_TRANSPORT}),\
	$(filter	no yes				,${MODEXP_CORE})))
  $(error ${USAGE})
endif

ifneq (${RPC_SERVER},$(if $(filter local,${RPC_CLIENT}),yes,no))
  $(error RPC_SERVER=yes is probably only useful with RPC_CLIENT=local)
endif

# Whether the RSA code should use the ModExp | ModExpS6 | ModExpA7 core.

ifeq (${MODEXP_CORE},yes)
  RSA_USE_MODEXP_CORE := 1
else
  RSA_USE_MODEXP_CORE := 0
endif

# Object files to build, initialized with ones we always want.
# There's a balance here between skipping files we don't strictly
# need and reducing the number of unnecessary conditionals in this
# makefile, so the working definition of "always want" is sometimes
# just "building this is harmless even if we don't use it."

OBJ = errorstrings.o hash.o asn1.o ecdsa.o rsa.o ${KS_OBJ}

# Object files to build when we're on a platform with direct access
# to our hardware (Verilog) cores.

CORE_OBJ = core.o csprng.o pbkdf2.o aes_keywrap.o modexp.o mkmif.o ${IO_OBJ}

# I/O bus to the FPGA
#
# IO_BUS = none | eim | i2c | fmc
#  none: no FPGA I/O bus
#   eim: EIM bus from Novena
#   i2c: older I2C bus from Novena
#   fmc: FMC bus from dev-bridge and alpha boards

ifeq (${IO_BUS},eim)
  IO_OBJ = hal_io_eim.o novena-eim.o
else ifeq (${IO_BUS},i2c)
  IO_OBJ = hal_io_i2c.o
else ifeq (${IO_BUS},fmc)
  IO_OBJ = hal_io_fmc.o
endif

# If we're building for STM32, position-independent code leads to some
# hard-to-debug function pointer errors. OTOH, if we're building for Linux
# (even on the Novena), we want to make it possible to build a shared library.

ifneq (${IO_BUS},fmc)
  CFLAGS += -fPIC
endif

# The mmap and flash keystore implementations are both server code.
#
# The volatile keystore (conventional memory) is client code, to
# support using the same API for things like PKCS #11 "session" objects.
#
# Default at the moment is mmap, since that should work on the Novena
# and we haven't yet written the flash code for the bridge board.

KS_OBJ = ks.o

ifeq (${KS},mmap)
  KS_OBJ += ks_mmap.o
else ifeq (${KS},volatile)
  KS_OBJ += ks_volatile.o
else ifeq (${KS},flash)
  KS_OBJ += ks_flash.o
endif

# RPC_CLIENT = none | local | remote | mixed
#   none: Build without RPC client
#   local: Build for Novena or dev-bridge, access FPGA cores directly.
#   remote: Build for other host, communicate with RPC server.
#   mixed: Do hashing locally in software, other functions remotely.
#
# RPC_SERVER = no | yes
#
# RPC_TRANSPORT = loopback | serial | daemon
#   loopback: communicate over loopback socket on Novena
#   serial: communicate over USB in serial pass-through mode
#   daemon: communicate over USB via a daemon, to arbitrate multiple clients
#
# RPC client locality flags passed here via CFLAGS are tested as
# integers in the C preprocessor, so the symbols we pass must be
# defined as macros in the C code, not enum tokens.

ifneq (${RPC_CLIENT},none)
  OBJ += rpc_api.o xdr.o
endif

ifeq (${RPC_TRANSPORT},serial)
  OBJ += slip.o
endif

RPC_CLIENT_OBJ = rpc_client.o
ifeq (${RPC_TRANSPORT},loopback)
  RPC_CLIENT_OBJ += rpc_client_loopback.o
else ifeq (${RPC_TRANSPORT},serial)
  RPC_CLIENT_OBJ += rpc_client_serial.o
else ifeq (${RPC_TRANSPORT},daemon)
  RPC_CLIENT_OBJ += rpc_client_daemon.o
endif

RPC_DISPATCH_OBJ = rpc_hash.o rpc_misc.o rpc_pkey.o

RPC_SERVER_OBJ = rpc_server.o
ifeq (${RPC_TRANSPORT},loopback)
  RPC_SERVER_OBJ += rpc_server_loopback.o
else ifeq (${RPC_TRANSPORT},serial)
  RPC_SERVER_OBJ += rpc_server_serial.o
endif

ifeq (${RPC_SERVER},yes)
  OBJ += ${RPC_SERVER_OBJ}
endif

ifeq (${RPC_CLIENT},none)
  OBJ += ${CORE_OBJ}
  CFLAGS += -DHAL_RSA_USE_MODEXP=${RSA_USE_MODEXP_CORE}
else ifeq (${RPC_CLIENT},local)
  OBJ += ${CORE_OBJ} ${RPC_CLIENT_OBJ} ${RPC_DISPATCH_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_LOCAL -DHAL_RSA_USE_MODEXP=${RSA_USE_MODEXP_CORE}
else ifeq (${RPC_CLIENT},remote)
  OBJ += ${RPC_CLIENT_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_REMOTE -DHAL_RSA_USE_MODEXP=0
else ifeq (${RPC_CLIENT},mixed)
  OBJ += ${RPC_CLIENT_OBJ} ${RPC_DISPATCH_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_MIXED -DHAL_RSA_USE_MODEXP=0
  KS = volatile
endif

TFMDIR		:= $(abspath ../thirdparty/libtfm)
CFLAGS		+= -g3 -Wall -std=c99 -Wno-strict-aliasing -I${TFMDIR}
LDFLAGS		:= -g3 -L${TFMDIR} -ltfm

CFLAGS		+= -DHAL_STATIC_HASH_STATE_BLOCKS=${STATIC_HASH_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HMAC_STATE_BLOCKS=${STATIC_HMAC_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_PKEY_STATE_BLOCKS=${STATIC_PKEY_STATE_BLOCKS}

all: ${LIB}
	cd tests; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@
	cd utils; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@

local:
	${MAKE} RPC_CLIENT=local RPC_TRANSPORT=none

client:
	${MAKE} RPC_CLIENT=remote

mixed:
	${MAKE} RPC_CLIENT=mixed KS=volatile

server:
	${MAKE} RPC_SERVER=yes

loopback:
	${MAKE} RPC_CLIENT=remote RPC_SERVER=yes RPC_TRANSPORT=loopback

daemon: cryptech_rpcd
#	${MAKE} RPC_CLIENT=mixed RPC_TRANSPORT=daemon
	${MAKE} RPC_CLIENT=remote RPC_TRANSPORT=daemon

cryptech_rpcd: daemon.o slip.o rpc_serial.o xdr.o
	${CC} ${CFLAGS} -o $@ $^ ${LDFLAGS}

${OBJ}: ${INC}

${LIB}: ${OBJ}
	${AR} rcs $@ $^

asn1.o rsa.o ecdsa.o:				asn1_internal.h
ecdsa.o:					ecdsa_curves.h
novena-eim.o hal_io_eim.o:			novena-eim.h
slip.o rpc_client_serial.o rpc_server_serial.o:	slip_internal.h
ks.o:						last_gasp_pin_internal.h

last_gasp_pin_internal.h:
	./utils/last_gasp_default_pin >$@

test: all
	export RPC_CLIENT RPC_SERVER
	cd tests; ${MAKE} -k $@

clean:
	rm -f *.o ${LIB}
	cd tests; ${MAKE} $@
	cd utils; ${MAKE} $@

distclean: clean
	rm -f TAGS

tags: TAGS

TAGS: *.[ch] tests/*.[ch] utils/*.[ch]
	etags $^

help usage:
	@echo ${USAGE}
