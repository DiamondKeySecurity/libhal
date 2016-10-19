# Copyright (c) 2016, NORDUnet A/S
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

"""
A Python interface to the Cryptech libhal RPC API.
"""

# A lot of this is hand-generated XDR data structure encoding.  If and
# when we ever convert the C library to use data structures processed
# by rpcgen, we may want to rewrite this code to use the output of
# something like https://github.com/floodlight/xdr.git -- in either
# case the generated code would just be for the data structures, we're
# not likely to want to use the full ONC RPC mechanism.

import os
import sys
import time
import uuid
import xdrlib
import serial

SLIP_END     = chr(0300)        # indicates end of packet
SLIP_ESC     = chr(0333)        # indicates byte stuffing
SLIP_ESC_END = chr(0334)        # ESC ESC_END means END data byte
SLIP_ESC_ESC = chr(0335)        # ESC ESC_ESC means ESC data byte

HAL_OK = 0

class HALError(Exception):
    "LibHAL error"

    table = [None]

    @classmethod
    def define(cls, **kw):
        assert len(kw) == 1
        name, text = kw.items()[0]
        e = type(name, (cls,), dict(__doc__ = text))
        cls.table.append(e)
        globals()[name] = e

HALError.define(HAL_ERROR_BAD_ARGUMENTS             = "Bad arguments given")
HALError.define(HAL_ERROR_UNSUPPORTED_KEY           = "Unsupported key type or key length")
HALError.define(HAL_ERROR_IO_SETUP_FAILED           = "Could not set up I/O with FPGA")
HALError.define(HAL_ERROR_IO_TIMEOUT                = "I/O with FPGA timed out")
HALError.define(HAL_ERROR_IO_UNEXPECTED             = "Unexpected response from FPGA")
HALError.define(HAL_ERROR_IO_OS_ERROR               = "Operating system error talking to FPGA")
HALError.define(HAL_ERROR_IO_BAD_COUNT              = "Bad byte count")
HALError.define(HAL_ERROR_CSPRNG_BROKEN             = "CSPRNG is returning nonsense")
HALError.define(HAL_ERROR_KEYWRAP_BAD_MAGIC         = "Bad magic number while unwrapping key")
HALError.define(HAL_ERROR_KEYWRAP_BAD_LENGTH        = "Length out of range while unwrapping key")
HALError.define(HAL_ERROR_KEYWRAP_BAD_PADDING       = "Non-zero padding detected unwrapping key")
HALError.define(HAL_ERROR_IMPOSSIBLE                = "\"Impossible\" error")
HALError.define(HAL_ERROR_ALLOCATION_FAILURE        = "Memory allocation failed")
HALError.define(HAL_ERROR_RESULT_TOO_LONG           = "Result too long for buffer")
HALError.define(HAL_ERROR_ASN1_PARSE_FAILED         = "ASN.1 parse failed")
HALError.define(HAL_ERROR_KEY_NOT_ON_CURVE          = "EC key is not on its purported curve")
HALError.define(HAL_ERROR_INVALID_SIGNATURE         = "Invalid signature")
HALError.define(HAL_ERROR_CORE_NOT_FOUND            = "Requested core not found")
HALError.define(HAL_ERROR_CORE_BUSY                 = "Requested core busy")
HALError.define(HAL_ERROR_KEYSTORE_ACCESS           = "Could not access keystore")
HALError.define(HAL_ERROR_KEY_NOT_FOUND             = "Key not found")
HALError.define(HAL_ERROR_KEY_NAME_IN_USE           = "Key name in use")
HALError.define(HAL_ERROR_NO_KEY_SLOTS_AVAILABLE    = "No key slots available")
HALError.define(HAL_ERROR_PIN_INCORRECT             = "PIN incorrect")
HALError.define(HAL_ERROR_NO_CLIENT_SLOTS_AVAILABLE = "No client slots available")
HALError.define(HAL_ERROR_FORBIDDEN                 = "Forbidden")
HALError.define(HAL_ERROR_XDR_BUFFER_OVERFLOW       = "XDR buffer overflow")
HALError.define(HAL_ERROR_RPC_TRANSPORT             = "RPC transport error")
HALError.define(HAL_ERROR_RPC_PACKET_OVERFLOW       = "RPC packet overflow")
HALError.define(HAL_ERROR_RPC_BAD_FUNCTION          = "Bad RPC function number")
HALError.define(HAL_ERROR_KEY_NAME_TOO_LONG         = "Key name too long")
HALError.define(HAL_ERROR_MASTERKEY_NOT_SET         = "Master key (Key Encryption Key) not set")
HALError.define(HAL_ERROR_MASTERKEY_FAIL            = "Master key generic failure")
HALError.define(HAL_ERROR_MASTERKEY_BAD_LENGTH      = "Master key of unacceptable length")
HALError.define(HAL_ERROR_KS_DRIVER_NOT_FOUND       = "Keystore driver not found")
HALError.define(HAL_ERROR_KEYSTORE_BAD_CRC          = "Bad CRC in keystore")
HALError.define(HAL_ERROR_KEYSTORE_BAD_BLOCK_TYPE   = "Unsupported keystore block type")
HALError.define(HAL_ERROR_KEYSTORE_LOST_DATA        = "Keystore appears to have lost data")
HALError.define(HAL_ERROR_BAD_ATTRIBUTE_LENGTH      = "Bad attribute length")
HALError.define(HAL_ERROR_ATTRIBUTE_NOT_FOUND       = "Attribute not found")
HALError.define(HAL_ERROR_NO_KEY_INDEX_SLOTS        = "No key index slots available")


def def_enum(text):
    for i, name in enumerate(text.translate(None, ",").split()):
        globals()[name] = i

def_enum('''
    RPC_FUNC_GET_VERSION,
    RPC_FUNC_GET_RANDOM,
    RPC_FUNC_SET_PIN,
    RPC_FUNC_LOGIN,
    RPC_FUNC_LOGOUT,
    RPC_FUNC_LOGOUT_ALL,
    RPC_FUNC_IS_LOGGED_IN,
    RPC_FUNC_HASH_GET_DIGEST_LEN,
    RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID,
    RPC_FUNC_HASH_GET_ALGORITHM,
    RPC_FUNC_HASH_INITIALIZE,
    RPC_FUNC_HASH_UPDATE,
    RPC_FUNC_HASH_FINALIZE,
    RPC_FUNC_PKEY_LOAD,
    RPC_FUNC_PKEY_FIND,
    RPC_FUNC_PKEY_GENERATE_RSA,
    RPC_FUNC_PKEY_GENERATE_EC,
    RPC_FUNC_PKEY_CLOSE,
    RPC_FUNC_PKEY_DELETE,
    RPC_FUNC_PKEY_GET_KEY_TYPE,
    RPC_FUNC_PKEY_GET_KEY_FLAGS,
    RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN,
    RPC_FUNC_PKEY_GET_PUBLIC_KEY,
    RPC_FUNC_PKEY_SIGN,
    RPC_FUNC_PKEY_VERIFY,
    RPC_FUNC_PKEY_LIST,
    RPC_FUNC_PKEY_RENAME,
    RPC_FUNC_PKEY_MATCH,
    RPC_FUNC_PKEY_SET_ATTRIBUTE,
    RPC_FUNC_PKEY_GET_ATTRIBUTE,
    RPC_FUNC_PKEY_DELETE_ATTRIBUTE,
''')

def_enum('''
    hal_digest_algorithm_none,
    hal_digest_algorithm_sha1,
    hal_digest_algorithm_sha224,
    hal_digest_algorithm_sha256,
    hal_digest_algorithm_sha512_224,
    hal_digest_algorithm_sha512_256,
    hal_digest_algorithm_sha384,
    hal_digest_algorithm_sha512
''')

def_enum('''
    HAL_KEY_TYPE_NONE = 0,
    HAL_KEY_TYPE_RSA_PRIVATE,
    HAL_KEY_TYPE_RSA_PUBLIC,
    HAL_KEY_TYPE_EC_PRIVATE,
    HAL_KEY_TYPE_EC_PUBLIC
''')

def_enum('''
    HAL_CURVE_NONE,
    HAL_CURVE_P256,
    HAL_CURVE_P384,
    HAL_CURVE_P521
''')

def_enum('''
    HAL_USER_NONE,
    HAL_USER_NORMAL,
    HAL_USER_SO,
    HAL_USER_WHEEL
''')

HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE     = (1 << 0)
HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT      = (1 << 1)
HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT     = (1 << 2)
HAL_KEY_FLAG_TOKEN                      = (1 << 3)


def cached_property(func):

    attr_name = "_" + func.__name__

    def wrapped(self):
        try:
            value = getattr(self, attr_name)
        except AttributeError:
            value = func(self)
            setattr(self, attr_name, value)
        return value

    wrapped.__name__ = func.__name__

    return property(wrapped)


class Handle(object):

    def __int__(self):
        return self.handle

    def __cmp__(self, other):
        return cmp(self.handle, int(other))


class Digest(Handle):

    def __init__(self, hsm, handle, algorithm):
        self.hsm       = hsm
        self.handle    = handle
        self.algorithm = algorithm

    def update(self, data):
        self.hsm.hash_update(self, data)

    def finalize(self, length = None):
        return self.hsm.hash_finalize(self, length or self.digest_length)

    @cached_property
    def algorithm_id(self):
        return self.hsm.hash_get_digest_algorithm_id(self.algorithm)

    @cached_property
    def digest_length(self):
        return self.hsm.hash_get_digest_length(self.algorithm)


class PKey(Handle):

    def __init__(self, hsm, handle, uuid):
        self.hsm    = hsm
        self.handle = handle
        self.uuid   = uuid

    def close(self):
        self.hsm.pkey_close(self)

    def delete(self):
        self.hsm.pkey_delete(self)

    @cached_property
    def key_type(self):
        return self.hsm.pkey_get_key_type(self)

    @cached_property
    def key_flags(self):
        return self.hsm.pkey_get_key_flags(self)

    @cached_property
    def public_key_len(self):
        return self.hsm.pkey_get_public_key_len(self)

    @cached_property
    def public_key(self):
        return self.hsm.pkey_get_public_key(self, self.public_key_len)

    def sign(self, hash = 0, data = "", length = 1024):
        return self.hsm.pkey_sign(self, hash, data, length)

    def verify(self, hash = 0, data = "", signature = None):
        self.hsm.pkey_verify(self, hash, data, signature)

    def set_attribute(self, type, value):
        self.hsm.pkey_set_attribute(self, type, value)

    def get_attribute(self, type):
        return self.hsm.pkey_get_attribute(self, type)

    def delete_attribute(self, type):
        self.hsm.pkey_delete_attribute(self, type)


class HSM(object):

    debug = True

    def _raise_if_error(self, status):
        if status != 0:
            raise HALError.table[status]()

    def __init__(self, device = os.getenv("CRYPTECH_RPC_CLIENT_SERIAL_DEVICE", "/dev/ttyUSB0")):
        while True:
            try:
                self.tty = serial.Serial(device, 921600, timeout=0.1)
                break
            except serial.SerialException:
                time.sleep(0.2)

    def _write(self, c):
        if self.debug:
            sys.stdout.write("{:02x}".format(ord(c)))
        self.tty.write(c)
        time.sleep(0.1)

    def _send(self, msg):       # Expects an xdrlib.Packer
        if self.debug:
            sys.stdout.write("+send: ")
        self._write(SLIP_END)
        for c in msg.get_buffer():
            if c == SLIP_END:
                self._write(SLIP_ESC)
                self._write(SLIP_ESC_END)
            elif c == SLIP_ESC:
                self._write(SLIP_ESC)
                self._write(SLIP_ESC_ESC)
            else:
                self._write(c)
        self._write(SLIP_END)
        if self.debug:
            sys.stdout.write("\n")

    def _recv(self, code):      # Returns an xdrlib.Unpacker
        if self.debug:
            sys.stdout.write("+recv: ")
        msg = []
        esc = False
        while True:
            c = self.tty.read(1)
            if self.debug and c:
                sys.stdout.write("{:02x}".format(ord(c)))
            if not c:
                time.sleep(0.1)
            elif c == SLIP_END and not msg:
                continue
            elif c == SLIP_END:
                if self.debug:
                    sys.stdout.write("\n")
                msg = xdrlib.Unpacker("".join(msg))
                if msg.unpack_uint() == code:
                    return msg
                msg = []
                if self.debug:
                    sys.stdout.write("+recv: ")
            elif c == SLIP_ESC:
                esc = True
            elif esc and c == SLIP_ESC_END:
                esc = False
                msg.append(SLIP_END)
            elif esc and c == SLIP_ESC_ESC:
                esc = False
                msg.append(SLIP_ESC)
            else:
                msg.append(c)

    def _pack(self, packer, args):
        for arg in args:
            if isinstance(arg, (int, long, Handle)):
                packer.pack_uint(arg)
            elif isinstance(arg, str):
                packer.pack_bytes(arg)
            elif isinstance(arg, uuid.UUID):
                packer.pack_bytes(arg.bytes)
            elif isinstance(arg, (list, tuple)):
                packer.pack_uint(len(arg))
                self._pack(packer, arg)
            else:
                raise RuntimeError("Don't know how to pack {!r} ({!r})".format(arg, type(arg)))

    def rpc(self, code, *args, **kwargs):
        client = kwargs.get("client", 0)
        packer = xdrlib.Packer()
        packer.pack_uint(code)
        packer.pack_uint(client)
        self._pack(packer, args)
        self._send(packer)
        unpacker = self._recv(code)
        client = unpacker.unpack_uint()
        self._raise_if_error(unpacker.unpack_uint())
        return unpacker

    def get_version(self):
        u = self.rpc(RPC_FUNC_GET_VERSION)
        r = u.unpack_uint()
        u.done()
        return r

    def get_random(self, n):
        u = self.rpc(RPC_FUNC_GET_RANDOM, n)
        r = u.unpack_bytes()
        u.done()
        return r

    def set_pin(self, user, pin):
        u = self.rpc(RPC_FUNC_SET_PIN, user, pin)
        u.done()

    def login(self, user, pin):
        u = self.rpc(RPC_FUNC_LOGIN, user, pin)
        u.done()

    def logout(self):
        u = self.rpc(RPC_FUNC_LOGOUT)
        u.done()

    def logout_all(self):
        u = self.rpc(RPC_FUNC_LOGOUT_ALL)
        u.done()

    def is_logged_in(self, user):
        u = self.rpc(RPC_FUNC_IS_LOGGED_IN, user)
        r = u.unpack_bool()
        u.done()
        return r

    def hash_get_digest_length(self, alg):
        u = self.rpc(RPC_FUNC_HASH_GET_DIGEST_LEN, alg)
        r = u.unpack_uint()
        u.done()
        return r

    def hash_get_digest_algorithm_id(self, alg, max_len = 256):
        u = self.rpc(RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID, alg, max_len)
        r = u.unpack_bytes()
        u.done()
        return r

    def hash_get_algorithm(self, handle):
        u = self.rpc(RPC_FUNC_HASH_GET_ALGORITHM, handle)
        r = u.unpack_uint()
        u.done()
        return r

    def hash_initialize(self, alg, key = "", client = 0, session = 0):
        u = self.rpc(RPC_FUNC_HASH_INITIALIZE, session, alg, key, client = client)
        r = Digest(self, u.unpack_uint(), alg)
        u.done()
        return r

    def hash_update(self, handle, data):
        u = self.rpc(RPC_FUNC_HASH_UPDATE, handle, data)
        u.done()

    def hash_finalize(self, handle, length = None):
        if length is None:
            length = self.hash_get_digest_length(self.hash_get_algorithm(handle))
        u = self.rpc(RPC_FUNC_HASH_FINALIZE, handle, length)
        r = u.unpack_bytes()
        u.done()
        return r

    def pkey_load(self, type, curve, der, flags = 0, client = 0, session = 0):
        u = self.rpc(RPC_FUNC_PKEY_LOAD, session, type, curve, der, flags, client = client)
        r = PKey(self, u.unpack_uint(), uuid.UUID(bytes = u.unpack_bytes()))
        u.done()
        return r

    def pkey_find(self, uuid, flags = 0, client = 0, session = 0):
        u = self.rpc(RPC_FUNC_PKEY_FIND, session, uuid, flags, client = client)
        r = PKey(self, u.unpack_uint(), uuid)
        u.done()
        return r

    def pkey_generate_rsa(self, keylen, exponent, flags = 0, client = 0, session = 0):
        u = self.rpc(RPC_FUNC_PKEY_GENERATE_RSA, session, keylen, exponent, flags, client = client)
        r = PKey(self, u.unpack_uint(), uuid.UUID(bytes = u.unpack_bytes()))
        u.done()
        return r

    def pkey_generate_ec(self, curve, flags = 0, client = 0, session = 0):
        u = self.rpc(RPC_FUNC_PKEY_GENERATE_EC, session, curve, flags, client = client)
        r = PKey(self, u.unpack_uint(), uuid.UUID(bytes = u.unpack_bytes()))
        u.done()
        return r

    def pkey_close(self, pkey):
        u = self.rpc(RPC_FUNC_PKEY_CLOSE, pkey)
        u.done()

    def pkey_delete(self, pkey):
        u = self.rpc(RPC_FUNC_PKEY_DELETE, pkey)
        u.done()

    def pkey_get_key_type(self, pkey):
        u = self.rpc(RPC_FUNC_PKEY_GET_KEY_TYPE, pkey)
        r = u.unpack_uint()
        u.done()
        return r

    def pkey_get_key_flags(self, pkey):
        u = self.rpc(RPC_FUNC_PKEY_GET_KEY_FLAGS, pkey)
        r = u.unpack_uint()
        u.done()
        return r

    def pkey_get_public_key_len(self, pkey):
        u = self.rpc(RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN, pkey)
        r = u.unpack_uint()
        u.done()
        return r

    def pkey_get_public_key(self, pkey, length = None):
        if length is None:
            length = self.pkey_get_public_key_len(pkey)
        u = self.rpc(RPC_FUNC_PKEY_GET_PUBLIC_KEY, pkey, length)
        r = u.unpack_bytes()
        u.done()
        return r

    def pkey_sign(self, pkey, hash = 0, data = "", length = 1024):
        u = self.rpc(RPC_FUNC_PKEY_SIGN, pkey, hash, data, length)
        r = u.unpack_bytes()
        u.done()
        return r

    def pkey_verify(self, pkey, hash = 0, data = "", signature = None):
        u = self.rpc(RPC_FUNC_PKEY_VERIFY, pkey, hash, data, signature)
        u.done()

    def pkey_list(self, flags = 0, client = 0, session = 0, length = 512):
        u = self.rpc(RPC_FUNC_PKEY_LIST, session, length, flags, client = client)
        r = tuple((u.unpack_uint(), u.unpack_uint(), u.unpack_uint(),
                   uuid.UUID(bytes = u.unpack_bytes()))
                  for i in xrange(u.unpack_uint()))
        u.done()
        return r

    def pkey_match(self, type = 0, curve = 0, flags = 0, attributes = (),
                   previous_uuid = uuid.UUID(int = 0), length = 512, client = 0, session = 0):
        u = self.rpc(RPC_FUNC_PKEY_MATCH, session, type, curve, flags,
                     attributes, length, previous_uuid, client = client)
        r = tuple(uuid.UUID(bytes = u.unpack_bytes())
                  for i in xrange(u.unpack_uint()))
        x = uuid.UUID(bytes = u.unpack_bytes())
        u.done()
        assert len(r) == 0 or x == r[-1]
        return r

    def pkey_set_attribute(self, pkey, type, value):
        u = self.rpc(RPC_FUNC_PKEY_SET_ATTRIBUTE, pkey, type, value)
        u.done()

    def pkey_get_attribute(self, pkey, type):
        u = self.rpc(RPC_FUNC_PKEY_GET_ATTRIBUTE, pkey, type)
        r = u.unpack_bytes()
        u.done()
        return r

    def pkey_delete_attribute(self, pkey, type):
        u = self.rpc(RPC_FUNC_PKEY_DELETE_ATTRIBUTE, pkey, type)
        u.done()


if __name__ == "__main__":

    def hexstr(s):
        return "".join("{:02x}".format(ord(c)) for c in s)

    hsm = HSM()

    print hex(hsm.get_version())

    print hexstr(hsm.get_random(16))

    h = hsm.hash_initialize(hal_digest_algorithm_sha256)
    h.update("Hi, Mom")
    print hexstr(h.finalize())

    h = hsm.hash_initialize(hal_digest_algorithm_sha256, key = "secret")
    h.update("Hi, Dad")
    print hexstr(h.finalize())

    k = hsm.pkey_generate_ec(HAL_CURVE_P256)
    print "{0.uuid} {0.key_type} {0.key_flags} {1}".format(k, hexstr(k.public_key))
    hsm.pkey_close(k)
    k = hsm.pkey_find(k.uuid)
    hsm.pkey_delete(k)

    for flags in (0, HAL_KEY_FLAG_TOKEN):
        for t, c, f, u in hsm.pkey_list(flags = flags):
            print u, t, c, f

    for f in (HAL_KEY_FLAG_TOKEN, 0):
        for u in hsm.pkey_match(flags = f):
            print u
