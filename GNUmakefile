# Copyright (c) 2015, NORDUnet A/S
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
OBJ		= core.o csprng.o hash.o aes_keywrap.o pbkdf2.o \
		  modexp.o rsa.o ecdsa.o asn1.o errorstrings.o \
		  ${IO_OBJ} ${RPC_OBJ} ${KS_OBJ}

IO_OBJ_EIM	= hal_io_eim.o novena-eim.o
IO_OBJ_I2C 	= hal_io_i2c.o

# Default I/O bus is EIM, override this to use I2C instead
IO_OBJ		= ${IO_OBJ_EIM}

RPC_OBJ_COMMON	= rpc_api.o rpc_hash.o rpc_misc.o rpc_pkey.o rpc_xdr.o
RPC_OBJ_CLIENT	= rpc_client.o rpc_client_loopback.o
RPC_OBJ_SERVER	= rpc_server.o rpc_server_loopback.o

# Default should be to build the RPC server code. We'll probably end up
# needing a makefile conditional to handle all this properly.
RPC_OBJ		= ${RPC_OBJ_COMMON} ${RPC_OBJ_CLIENT} ${RPC_OBJ_SERVER}

KS_OBJ_COMMON	= ks.o
KS_OBJ_MMAP	= ${KS_OBJ_COMMON} ks_mmap.o
KS_OBJ_VOLATILE	= ${KS_OBJ_COMMON} ks_volatile.o
KS_OBJ_FLASH	= ${KS_OBJ_COMMON} ks_flash.o

# The mmap and flash keystore implementations are both server code.
#
# The volatile keystore (conventional memory) is client code, to
# support using the same API for things like PKCS #11 "session" objects.
#
# Default at the moment is mmap, since that should work on the Novena
# and we haven't yet written the flash code for the bridge board.

KS_OBJ		= ${KS_OBJ_MMAP}

TFMDIR		:= $(abspath ../thirdparty/libtfm)
CFLAGS		+= -g3 -Wall -fPIC -std=c99 -I${TFMDIR}
LDFLAGS		:= -g3 -L${TFMDIR} -ltfm

CFLAGS		+= -DHAL_STATIC_HASH_STATE_BLOCKS=${STATIC_HASH_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HMAC_STATE_BLOCKS=${STATIC_HMAC_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_PKEY_STATE_BLOCKS=${STATIC_PKEY_STATE_BLOCKS}

all: ${LIB}
	cd tests; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@
	cd utils; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@

${OBJ}: ${INC}

${LIB}: ${OBJ}
	${AR} rcs $@ $^

asn1.o rsa.o ecdsa.o:		asn1_internal.h
ecdsa.o:			ecdsa_curves.h
novena-eim.o hal_io_eim.o:	novena-eim.h

test: all
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
