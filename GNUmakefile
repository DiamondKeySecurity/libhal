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

# Number of static hash and HMAC state blocks to allocate

STATIC_HASH_STATE_BLOCKS = 10
STATIC_HMAC_STATE_BLOCKS = 4

INC		= hal.h
LIB		= libhal.a
OBJ		= ${IO_OBJ} core.o csprng.o hash.o aes_keywrap.o pbkdf2.o \
		  modexp.o rsa.o ecdsa.o asn1.o errorstrings.o ${RPC_OBJ}
IO_OBJ_EIM	= hal_io_eim.o novena-eim.o
IO_OBJ_I2C 	= hal_io_i2c.o

# Default I/O bus is EIM, override this to use I2C instead
IO_OBJ		= ${IO_OBJ_EIM}

RPC_OBJ_COMMON	= hal_rpc.o rpc_hash.o
RPC_OBJ_CLIENT	= ${RPC_OBJ_COMMON} rpc_client.o
RPC_OBJ_SERVER	= ${RPC_OBJ_COMMON} rpc_misc.o rpc_pkey.o

# Default should be to build the RPC server code, but we haven't
# written even the skeleton of that yet.  We'll probably end up
# needing a makefile conditional to handle all this properly
RPC_OBJ		= ${RPC_OBJ_CLIENT}

TFMDIR		:= $(abspath ../thirdparty/libtfm)
CFLAGS		+= -g3 -Wall -fPIC -std=c99 -I${TFMDIR} -DHAL_ECDSA_DEBUG_ONLY_STATIC_TEST_VECTOR_RANDOM=1
LDFLAGS		:= -g3 -L${TFMDIR} -ltfm

CFLAGS		+= -DHAL_STATIC_HASH_STATE_BLOCKS=${STATIC_HASH_STATE_BLOCKS}
CFLAGS		+= -DHAL_STATIC_HMAC_STATE_BLOCKS=${STATIC_HMAC_STATE_BLOCKS}

all: ${LIB}
	cd tests; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@
	cd utils; ${MAKE} CFLAGS='${CFLAGS} -I..' LDFLAGS='${LDFLAGS}' $@

${OBJ}: ${INC}

${LIB}: ${OBJ}
	${AR} rcs $@ $^

asn1.o rsa.o ecdsa.o: asn1_internal.h

ecdsa.o: ecdsa_curves.h

test: all
	cd tests; ${MAKE} -k $@

clean:
	rm -f ${OBJ} ${LIB}
	cd tests; ${MAKE} $@
	cd utils; ${MAKE} $@

distclean: clean
	rm -f TAGS

tags: TAGS

TAGS: *.[ch] tests/*.[ch]
	etags $^
