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

OBJ		= errorstrings.o ${CORE_OBJ} ${IO_OBJ} ${RPC_OBJ} ${KS_OBJ}
CORE_OBJ	:= core.o csprng.o hash.o aes_keywrap.o pbkdf2.o \
		   modexp.o rsa.o ecdsa.o asn1.o

USAGE = "usage: make [IO_BUS=eim|i2c|fmc] [RPC_CLIENT=local|remote|mixed] [RPC_SERVER=yes] [KS=mmap|volatile|flash]"

# I/O bus to the FPGA
#
# IO_BUS = eim | i2c | fmc
#   eim: EIM bus from Novena
#   i2c: older I2C bus from Novena
#   fmc: FMC bus from dev-bridge board

IO_BUS ?= eim
ifeq (${IO_BUS},eim)
  IO_OBJ = hal_io_eim.o novena-eim.o
else ifeq (${IO_BUS},i2c)
  IO_OBJ = hal_io_i2c.o
else ifeq (${IO_BUS},fmc)
  IO_OBJ = hal_io_fmc.o
endif

# RPC_CLIENT = local | remote | mixed
#   local: Build for Novena or dev-bridge, access FPGA cores directly.
#   remote: Build for other host, communicate with RPC server.
#   mixed: Do hashing locally in software, other functions remotely.
#
# RPC_SERVER = yes
#
# RPC_TRANSPORT = loopback | serial
#   loopback: communicate over loopback socket on Novena
#   serial: communicate over USB in serial pass-through mode

RPC_CORE_OBJ = rpc_api.o rpc_hash.o rpc_misc.o rpc_pkey.o

ifdef RPC_SERVER
  RPC_SERVER_OBJ = rpc_server.o ${RPC_CORE_OBJ}
  RPC_TRANSPORT ?= serial
endif

ifdef RPC_CLIENT
  RPC_CLIENT_OBJ = rpc_client.o
  ifeq (${RPC_CLIENT},local)
    RPC_CLIENT_OBJ += ${RPC_CORE_OBJ}
  else
    RPC_TRANSPORT ?= serial
    ifeq (${RPC_CLIENT},mixed)
      CFLAGS += -DHAL_ENABLE_SOFTWARE_HASH_CORES
    endif
    ifndef RPC_SERVER
      # If we're only building a remote RPC client lib, don't include
      # the modules that access the FPGA cores.
      CORE_OBJ :=
      IO_OBJ :=
    endif
  endif
endif

ifdef RPC_TRANSPORT
  RPC_TRANSPORT_OBJ = xdr.o
  ifeq (${RPC_TRANSPORT},loopback)
    ifdef RPC_SERVER
      RPC_TRANSPORT_OBJ += rpc_server_loopback.o
    endif
    ifdef RPC_CLIENT
      RPC_TRANSPORT_OBJ += rpc_client_loopback.o
    endif
  else ifeq (${RPC_TRANSPORT},serial)
    RPC_TRANSPORT_OBJ += slip.o
    ifdef RPC_SERVER
      RPC_TRANSPORT_OBJ += rpc_server_serial.o
    endif
    ifdef RPC_CLIENT
      RPC_TRANSPORT_OBJ += rpc_client_serial.o
    endif
  endif
endif

RPC_OBJ = ${RPC_SERVER_OBJ} ${RPC_CLIENT_OBJ} ${RPC_TRANSPORT_OBJ}

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

TFMDIR		:= $(abspath ../thirdparty/libtfm)
CFLAGS		+= -g3 -Wall -fPIC -std=c99 -I${TFMDIR} -DHAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM=1
LDFLAGS		:= -g3 -L${TFMDIR} -ltfm

CFLAGS		+= -DHAL_STATIC_HASH_STATE_BLOCKS=${STATIC_HASH_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HMAC_STATE_BLOCKS=${STATIC_HMAC_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_PKEY_STATE_BLOCKS=${STATIC_PKEY_STATE_BLOCKS}
CFLAGS		+= -DRPC_CLIENT=${RPC_CLIENT_FLAG}

all: ${LIB}
	cd tests; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@
ifneq (${CORE_OBJ},)
	cd utils; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@
endif

${OBJ}: ${INC}

${LIB}: ${OBJ}
	${AR} rcs $@ $^

asn1.o rsa.o ecdsa.o:		asn1_internal.h
ecdsa.o:			ecdsa_curves.h
novena-eim.o hal_io_eim.o:	novena-eim.h
slip.o rpc_client_serial.o rpc_server_serial.o:	slip_internal.h

test: all
	export RPC_CLIENT RPC_SERVER
	cd tests; ${MAKE} -k $@

clean:
	rm -f ${OBJ} ${LIB}
	cd tests; ${MAKE} $@
	cd utils; ${MAKE} $@

distclean: clean
	rm -f TAGS

tags: TAGS

TAGS: *.[ch] tests/*.[ch] utils/*.[ch]
	etags $^
