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

STATIC_CORE_STATE_BLOCKS = 32
STATIC_HASH_STATE_BLOCKS = 10
STATIC_HMAC_STATE_BLOCKS = 4
STATIC_PKEY_STATE_BLOCKS = 32
STATIC_KS_VOLATILE_SLOTS = 128

INC		= hal.h hal_internal.h
LIB		= libhal.a

# Error checking on known control options, some of which allow the user entirely too much rope.

USAGE := "usage: ${MAKE} [IO_BUS=eim|i2c|fmc] [RPC_MODE=none|server|client-simple|client-mixed] [KS=mmap|flash] [RPC_TRANSPORT=none|loopback|serial|daemon] [MODEXP_CORE=no|yes]"

IO_BUS		?= none
KS		?= flash
RPC_MODE	?= none
RPC_TRANSPORT	?= none
MODEXP_CORE	?= no

ifeq (,$(and \
	$(filter	none eim i2c fmc			,${IO_BUS}),\
	$(filter	none server client-simple client-mixed	,${RPC_MODE}),\
	$(filter	mmap flash				,${KS}),\
	$(filter	none loopback serial daemon		,${RPC_TRANSPORT}),\
	$(filter	no yes					,${MODEXP_CORE})))
  $(error ${USAGE})
endif

$(info Building libhal with configuration IO_BUS=${IO_BUS} RPC_MODE=${RPC_MODE} KS=${KS} RPC_TRANSPORT=${RPC_TRANSPORT} MODEXP_CORE=${MODEXP_CORE})

# Whether the RSA code should use the ModExp | ModExpS6 | ModExpA7 core.

ifeq "${MODEXP_CORE}" "yes"
  RSA_USE_MODEXP_CORE := 1
else
  RSA_USE_MODEXP_CORE := 0
endif

# Object files to build, initialized with ones we always want.
# There's a balance here between skipping files we don't strictly
# need and reducing the number of unnecessary conditionals in this
# makefile, so the working definition of "always want" is sometimes
# just "building this is harmless even if we don't use it."

OBJ += errorstrings.o hash.o asn1.o ecdsa.o rsa.o xdr.o slip.o
OBJ += rpc_api.o rpc_hash.o uuid.o rpc_pkcs1.o crc32.o

# Object files to build when we're on a platform with direct access
# to our hardware (Verilog) cores.

CORE_OBJ = core.o csprng.o pbkdf2.o aes_keywrap.o modexp.o mkmif.o ${IO_OBJ}

# I/O bus to the FPGA
#
# IO_BUS = none | eim | i2c | fmc
#  none:	No FPGA I/O bus
#   eim:	EIM bus from Novena
#   i2c:	Older I2C bus from Novena
#   fmc:	FMC bus from dev-bridge and alpha boards

ifeq "${IO_BUS}" "eim"
  IO_OBJ = hal_io_eim.o novena-eim.o
else ifeq "${IO_BUS}" "i2c"
  IO_OBJ = hal_io_i2c.o
else ifeq "${IO_BUS}" "fmc"
  IO_OBJ = hal_io_fmc.o
endif

# If we're building for STM32, position-independent code leads to some
# hard-to-debug function pointer errors. OTOH, if we're building for Linux
# (even on the Novena), we want to make it possible to build a shared library.

ifneq "${IO_BUS}" "fmc"
  CFLAGS += -fPIC
endif

# The keystore code has mutated a bit with the new API, and the Makefile,
# probably needs more extensive changes to track that.
#
# In the old world, the volatile keystore was for the client side,
# while the flash and mmap keystores were for the server side (on the
# Alpha and the Novena, respectively).
#
# In the new world, all keystores are on the server side, and the
# volatile keystore is always present, to support things like PKCS #11
# "session" objects.
#
# The mmap keystore hasn't been rewritten for the new API yet.

KS_OBJ = ks_index.o ks_attribute.o ks_volatile.o

ifeq "${KS}" "mmap"
  KS_OBJ += ks_mmap.o
else ifeq "${KS}" "flash"
  KS_OBJ += ks_flash.o mkm.o
endif

# RPC_MODE = none | server | client-simple | client-mixed
#   none:		Build without RPC client, use cores directly.
#   server:		Build for server side of RPC (HSM), use cores directly.
#   client-simple:	Build for other host, communicate with cores via RPC server.
#   client-mixed:	Like client-simple but do hashing locally in software and
#			support a local keystore (for PKCS #11 public keys, etc)
#
# RPC_TRANSPORT = none | loopback | serial | daemon
#   loopback:		Communicate over loopback socket on Novena
#   serial:		Communicate over USB in serial pass-through mode
#   daemon:		Communicate over USB via a daemon, to arbitrate multiple clients
#
# Note that RPC_MODE setting also controls the RPC_CLIENT setting passed to the C
# preprocessor via CFLAGS.  Whatever we pass here must evaluate to an integer in
# the C preprocessor: we can use symbolic names so long as they're defined as macros
# in the C code, but we can't use things like C enum symbols.

RPC_CLIENT_OBJ = rpc_client.o

ifeq "${RPC_TRANSPORT}" "loopback"
  RPC_CLIENT_OBJ += rpc_client_loopback.o
else ifeq "${RPC_TRANSPORT}" "serial"
  RPC_CLIENT_OBJ += rpc_serial.o rpc_client_serial.o
else ifeq "${RPC_TRANSPORT}" "daemon"
  RPC_CLIENT_OBJ += rpc_client_daemon.o
endif

RPC_SERVER_OBJ = ${KS_OBJ} rpc_misc.o rpc_pkey.o rpc_server.o

ifeq "${RPC_TRANSPORT}" "loopback"
  RPC_SERVER_OBJ += rpc_server_loopback.o
else ifeq "${RPC_TRANSPORT}" "serial"
  RPC_SERVER_OBJ += rpc_server_serial.o
endif

ifeq "${RPC_MODE}" "none"
  OBJ += ${CORE_OBJ}
  CFLAGS += -DHAL_RSA_USE_MODEXP=${RSA_USE_MODEXP_CORE}
else ifeq "${RPC_MODE}" "server"
  OBJ += ${CORE_OBJ} ${RPC_SERVER_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_LOCAL -DHAL_RSA_USE_MODEXP=${RSA_USE_MODEXP_CORE}
else ifeq "${RPC_MODE}" "client-simple"
  OBJ += ${RPC_CLIENT_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_REMOTE -DHAL_RSA_USE_MODEXP=0 -DHAL_ONLY_USE_SOFTWARE_HASH_CORES=1
else ifeq "${RPC_MODE}" "client-mixed"
  OBJ += ${RPC_CLIENT_OBJ}
  CFLAGS += -DRPC_CLIENT=RPC_CLIENT_MIXED -DHAL_RSA_USE_MODEXP=0 -DHAL_ONLY_USE_SOFTWARE_HASH_CORES=1
endif

ifndef CRYPTECH_ROOT
  CRYPTECH_ROOT := $(abspath ../..)
endif

LIBTFM_SRC	?= ${CRYPTECH_ROOT}/sw/thirdparty/libtfm
LIBTFM_BLD	?= ${LIBTFM_SRC}

# tfm.h is a generated file, because our Makefile customizes a few
# settings from the upstream libtfm distribution.  Because of this, we
# need to search the libtfm build directory, not the libtfm source
# directory.

CFLAGS		+= -g3 -Wall -std=c99 -Wno-strict-aliasing
CFLAGS		+= -DHAL_STATIC_CORE_STATE_BLOCKS=${STATIC_CORE_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HASH_STATE_BLOCKS=${STATIC_HASH_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HMAC_STATE_BLOCKS=${STATIC_HMAC_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_PKEY_STATE_BLOCKS=${STATIC_PKEY_STATE_BLOCKS}
CFLAGS		+= -I${CRYPTECH_ROOT}/sw/libhal
CFLAGS		+= -I${LIBTFM_BLD}

# Enable software hash cores everywhere for now.  In theory, there might be situations
# where we don't want them on the HSM, but they're relatively harmless, and the bootstrap
# sequence on new hardware works a lot better when we can log in before loading the FPGA.

CFLAGS		+= -DHAL_ENABLE_SOFTWARE_HASH_CORES=1

export CFLAGS
export RPC_MODE

all: ${LIB}
	cd tests; ${MAKE} $@
	cd utils; ${MAKE} $@

client:
	${MAKE} RPC_MODE=client-simple RPC_TRANSPORT=daemon

mixed:
	${MAKE} RPC_MODE=client-mixed RPC_TRANSPORT=daemon

server:
	${MAKE} RPC_MODE=server RPC_TRANSPORT=serial IO_BUS=fmc

serial:
	${MAKE} RPC_MODE=client-mixed RPC_TRANSPORT=serial

daemon: mixed

.PHONY: client mixed server serial daemon

${OBJ}: ${INC}

${LIB}: ${OBJ}
	${AR} rcs $@ $^

asn1.o rsa.o ecdsa.o:				asn1_internal.h
ecdsa.o:					ecdsa_curves.h
novena-eim.o hal_io_eim.o:			novena-eim.h
slip.o rpc_client_serial.o rpc_server_serial.o:	slip_internal.h
ks_flash.o:					last_gasp_pin_internal.h

last_gasp_pin_internal.h:
	./utils/last_gasp_default_pin >$@

test: all
	export RPC_MODE
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
