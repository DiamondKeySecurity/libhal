# Copyright (c) 2015-2018, NORDUnet A/S
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

LIBHAL_SRC	?= ..
LIBHAL_BLD	?= ${LIBHAL_SRC}
LIBTFM_BLD	?= ../../thirdparty/libtfm

LIBS		= ${LIBHAL_BLD}/libhal.a ${LIBTFM_BLD}/libtfm.a

CFLAGS		?= -g3 -Wall -fPIC -std=c99 -I${LIBHAL_SRC} -I${LIBTFM_BLD}

# Which tests to build depends on how the library was compiled.

CORE_TESTS	= test-aes-key-wrap test-hash test-pbkdf2 test-ecdsa test-bus test-trng test-rsa test-mkmif
SERVER_TESTS	= test-rpc_server
CLIENT_TESTS	= test-rpc_hash test-rpc_pkey test-rpc_get_version test-rpc_get_random test-rpc_login test-rpc_bighash test-xdr test-rpc_hashsig

ALL_TESTS	= ${CORE_TESTS} ${SERVER_TESTS} ${CLIENT_TESTS}

ifeq "${RPC_MODE}" "none"

  BIN += ${CORE_TESTS}

else ifeq "${RPC_MODE}" "server"

  BIN += ${CORE_TESTS} ${SERVER_TESTS}

else

  BIN += ${CLIENT_TESTS}

endif

all: ${BIN}

test: all
	for i in ${BIN}; do (set -x; ./$$i); done

clean distclean:
	rm -f *.o ${ALL_TESTS}

${BIN}: %: %.o ${LIBS}
	${CC} ${CFLAGS} -o $@ $^ ${LDFLAGS}

%.o: %.c ${LIBHAL_SRC}/*.h ${LIBTFM_BLD}/tfm.h
	${CC} ${CFLAGS} -c -o $@ $<

test-rpc_hashsig.o: test-hashsig.h
