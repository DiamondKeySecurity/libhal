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

USAGE = "usage: make [IO_BUS=eim|i2c|fmc] [RPC_CLIENT=local|remote|mixed] [RPC_SERVER=yes] [KS=mmap|volatile|flash]"

OBJ = errorstrings.o
CORE_OBJ = core.o ${HASH_OBJ} ${MISC_OBJ} ${PKEY_OBJ} ${PKEY2_OBJ} ${KS_OBJ} ${IO_OBJ}
HASH_OBJ = hash.o
MISC_OBJ = csprng.o pbkdf2.o
PKEY_OBJ = asn1.o ecdsa.o rsa.o
PKEY2_OBJ = aes_keywrap.o modexp.o

# I/O bus to the FPGA
#
# IO_BUS = eim | i2c | fmc
#   eim: EIM bus from Novena
#   i2c: older I2C bus from Novena
#   fmc: FMC bus from dev-bridge and alpha boards

IO_BUS ?= eim
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
KS ?= mmap
ifeq (${KS},mmap)
  KS_OBJ += ks_mmap.o
else ifeq (${KS},volatile)
  KS_OBJ += ks_volatile.o
else ifeq (${KS},flash)
  KS_OBJ += ks_flash.o
endif

# RPC_CLIENT = local | remote | mixed
#   local: Build for Novena or dev-bridge, access FPGA cores directly.
#   remote: Build for other host, communicate with RPC server.
#   mixed: Do hashing locally in software, other functions remotely.
#
# RPC_SERVER = yes
#
# RPC_TRANSPORT = loopback | serial | daemon
#   loopback: communicate over loopback socket on Novena
#   serial: communicate over USB in serial pass-through mode
#   daemon: communicate over USB via a daemon, to arbitrate multiple clients

RPC_TRANSPORT ?= daemon

RPC_CLIENT_OBJ = rpc_api.o rpc_client.o xdr.o
ifeq (${RPC_TRANSPORT},loopback)
  RPC_CLIENT_OBJ += rpc_client_loopback.o
else ifeq (${RPC_TRANSPORT},serial)
  RPC_CLIENT_OBJ += rpc_client_serial.o slip.o
else ifeq (${RPC_TRANSPORT},daemon)
  RPC_CLIENT_OBJ += rpc_client_daemon.o
endif

RPC_DISPATCH_OBJ = rpc_hash.o rpc_misc.o rpc_pkey.o

RPC_SERVER_OBJ = rpc_api.o rpc_server.o xdr.o ${RPC_DISPATCH_OBJ}
ifeq (${RPC_TRANSPORT},loopback)
  RPC_SERVER_OBJ += rpc_server_loopback.o
else ifeq (${RPC_TRANSPORT},serial)
  RPC_SERVER_OBJ += rpc_server_serial.o slip.o
endif

# Not building any of the RPC stuff, access FPGA cores directly.
ifndef RPC_CLIENT
  ifndef RPC_SERVER
    OBJ += ${CORE_OBJ}
  endif
endif

# Building the RPC server.
ifdef RPC_SERVER
  OBJ += ${CORE_OBJ} ${RPC_SERVER_OBJ}
endif

# Building the RPC client, in all its variations.
ifdef RPC_CLIENT
  OBJ += ${RPC_CLIENT_OBJ}
  ifeq (${RPC_CLIENT},local)
    OBJ += ${CORE_OBJ} ${RPC_DISPATCH_OBJ}
  else
    CFLAGS += -DHAL_RSA_USE_MODEXP=0
    OBJ +=  ${PKEY_OBJ}
    ifeq (${RPC_CLIENT},mixed)
      KS = volatile
      OBJ += ${HASH_OBJ} ${PKEY2_OBJ} ${RPC_DISPATCH_OBJ} ${KS_OBJ}
    endif
  endif
endif

# RPC client locality, for rpc_client.c. This has to be kept in sync with
# hal_internal.h. Yeah, it's ugly, but the C preprocessor can only
# compare integers, not strings.

ifeq (${RPC_CLIENT},local)
  RPC_CLIENT_FLAG = 0
else ifeq (${RPC_CLIENT},remote)
  RPC_CLIENT_FLAG = 1
else ifeq (${RPC_CLIENT},mixed)
  RPC_CLIENT_FLAG = 2
endif
ifdef RPC_CLIENT_FLAG
CFLAGS		+= -DRPC_CLIENT=${RPC_CLIENT_FLAG}
endif

TFMDIR		:= $(abspath ../thirdparty/libtfm)
CFLAGS		+= -g3 -Wall -std=c99 -I${TFMDIR}
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
