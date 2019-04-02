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

BIN		= $(if $(wildcard ${LIBHAL_BLD}/hal_io_eim.o),eim_peek_poke) $(if $(wildcard ${LIBHAL_BLD}/core.o),cores) pkey-export pkey-import pkey

all: ${BIN}

clean:
	rm -f *.o ${BIN}

${BIN}: %: %.o ${LIBS}
	${CC} ${CFLAGS} -o $@ $^ ${LDFLAGS}

%.o: %.c ${LIBHAL_SRC}/*.h
	${CC} ${CFLAGS} -c -o $@ $<
