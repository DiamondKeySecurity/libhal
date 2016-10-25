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
import contextlib

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


class Enum(int):

    def __new__(cls, name, value):
        self = int.__new__(cls, value)
        self._name = name
        setattr(self.__class__, name, self)
        return self

    def __str__(self):
        return self._name

    def __repr__(self):
        return "<Enum:{0.__class__.__name__} {0._name}:{0:d}>".format(self)

    _counter = 0

    @classmethod
    def define(cls, names):
        symbols = []
        for name in names.translate(None, "{}").split(","):
            if "=" in name:
                name, sep, expr = name.partition("=")
                cls._counter = eval(expr.strip())
            if not isinstance(cls._counter, int):
                raise TypeError
            symbols.append(cls(name.strip(), cls._counter))
            cls._counter += 1
        cls.index = dict((int(symbol),  symbol) for symbol in symbols)
        globals().update((symbol._name, symbol) for symbol in symbols)

    def xdr_packer(self, packer):
        packer.pack_uint(self)


class RPCFunc(Enum): pass

RPCFunc.define('''
    RPC_FUNC_GET_VERSION = 0,
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

class HALDigestAlgorithm(Enum): pass

HALDigestAlgorithm.define('''
    HAL_DIGEST_ALGORITHM_NONE,
    HAL_DIGEST_ALGORITHM_SHA1,
    HAL_DIGEST_ALGORITHM_SHA224,
    HAL_DIGEST_ALGORITHM_SHA256,
    HAL_DIGEST_ALGORITHM_SHA512_224,
    HAL_DIGEST_ALGORITHM_SHA512_256,
    HAL_DIGEST_ALGORITHM_SHA384,
    HAL_DIGEST_ALGORITHM_SHA512
''')

class HALKeyType(Enum): pass

HALKeyType.define('''
    HAL_KEY_TYPE_NONE,
    HAL_KEY_TYPE_RSA_PRIVATE,
    HAL_KEY_TYPE_RSA_PUBLIC,
    HAL_KEY_TYPE_EC_PRIVATE,
    HAL_KEY_TYPE_EC_PUBLIC
''')

class HALCurve(Enum): pass

HALCurve.define('''
    HAL_CURVE_NONE,
    HAL_CURVE_P256,
    HAL_CURVE_P384,
    HAL_CURVE_P521
''')

class HALUser(Enum): pass

HALUser.define('''
    HAL_USER_NONE,
    HAL_USER_NORMAL,
    HAL_USER_SO,
    HAL_USER_WHEEL
''')

HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE     = (1 << 0)
HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT      = (1 << 1)
HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT     = (1 << 2)
HAL_KEY_FLAG_TOKEN                      = (1 << 3)
HAL_KEY_FLAG_PUBLIC                     = (1 << 4)

class Attribute(object):

    def __init__(self, type, value):
        self.type  = type
        self.value = value

    def xdr_packer(self, packer):
        packer.pack_uint(self.type)
        packer.pack_bytes(self.value)


class UUID(uuid.UUID):

    def xdr_packer(self, packer):
        packer.pack_bytes(self.bytes)


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

    def xdr_packer(self, packer):
        packer.pack_uint(self.handle)


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

    def set_attribute(self, attr_type, attr_value = None):
        self.hsm.pkey_set_attribute(self, attr_type, attr_value)

    def get_attribute(self, attr_type):
        return self.hsm.pkey_get_attribute(self, attr_type)

    def delete_attribute(self, attr_type):
        self.hsm.pkey_delete_attribute(self, attr_type)


class HSM(object):

    debug = False

    _send_delay = 0             # 0.1

    def _raise_if_error(self, status):
        if status != 0:
            raise HALError.table[status]()

    def __init__(self, device = os.getenv("CRYPTECH_RPC_CLIENT_SERIAL_DEVICE", "/dev/ttyUSB0")):
        while True:
            try:
                self.tty = serial.Serial(device, 921600, timeout = 0.1)
                break
            except serial.SerialException:
                time.sleep(0.2)

    def _write(self, c):
        if self.debug:
            sys.stdout.write("{:02x}".format(ord(c)))
        self.tty.write(c)
        if self._send_delay > 0:
            time.sleep(self._send_delay)

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
            if hasattr(arg, "xdr_packer"):
                arg.xdr_packer(packer)
            else:
                try:
                    func = getattr(self, "_pack_" + type(arg).__name__)
                except AttributeError:
                    raise RuntimeError("Don't know how to pack {!r} ({!r})".format(arg, type(arg)))
                else:
                    func(packer, arg)

    @staticmethod
    def _pack_int(packer, arg):
        packer.pack_uint(arg)

    @staticmethod
    def _pack_str(packer, arg):
        packer.pack_bytes(arg)

    def _pack_tuple(self, packer, arg):
        packer.pack_uint(len(arg))
        self._pack(packer, arg)

    _pack_long = _pack_int
    _pack_list = _pack_tuple

    @contextlib.contextmanager
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
        yield unpacker
        unpacker.done()

    def get_version(self):
        with self.rpc(RPC_FUNC_GET_VERSION) as r:
            return r.unpack_uint()

    def get_random(self, n):
        with self.rpc(RPC_FUNC_GET_RANDOM, n) as r:
            return r.unpack_bytes()

    def set_pin(self, user, pin):
        with self.rpc(RPC_FUNC_SET_PIN, user, pin):
            return

    def login(self, user, pin):
        with self.rpc(RPC_FUNC_LOGIN, user, pin):
            return

    def logout(self):
        with self.rpc(RPC_FUNC_LOGOUT):
            return

    def logout_all(self):
        with self.rpc(RPC_FUNC_LOGOUT_ALL):
            return

    def is_logged_in(self, user):
        with self.rpc(RPC_FUNC_IS_LOGGED_IN, user) as r:
            return r.unpack_bool()

    def hash_get_digest_length(self, alg):
        with self.rpc(RPC_FUNC_HASH_GET_DIGEST_LEN, alg) as r:
            return r.unpack_uint()

    def hash_get_digest_algorithm_id(self, alg, max_len = 256):
        with self.rpc(RPC_FUNC_HASH_GET_DIGEST_ALGORITHM_ID, alg, max_len) as r:
            return r.unpack_bytes()

    def hash_get_algorithm(self, handle):
        with self.rpc(RPC_FUNC_HASH_GET_ALGORITHM, handle) as r:
            return HALDigestAlgorithm.index[r.unpack_uint()]

    def hash_initialize(self, alg, key = "", client = 0, session = 0):
        with self.rpc(RPC_FUNC_HASH_INITIALIZE, session, alg, key, client = client) as r:
            return Digest(self, r.unpack_uint(), alg)

    def hash_update(self, handle, data):
        with self.rpc(RPC_FUNC_HASH_UPDATE, handle, data):
            return

    def hash_finalize(self, handle, length = None):
        if length is None:
            length = self.hash_get_digest_length(self.hash_get_algorithm(handle))
        with self.rpc(RPC_FUNC_HASH_FINALIZE, handle, length) as r:
            return r.unpack_bytes()

    def pkey_load(self, type, curve, der, flags = 0, client = 0, session = 0):
        with self.rpc(RPC_FUNC_PKEY_LOAD, session, type, curve, der, flags, client = client) as r:
            return PKey(self, r.unpack_uint(), UUID(bytes = r.unpack_bytes()))

    def pkey_find(self, uuid, flags = 0, client = 0, session = 0):
        with self.rpc(RPC_FUNC_PKEY_FIND, session, uuid, flags, client = client) as r:
            return PKey(self, r.unpack_uint(), uuid)

    def pkey_generate_rsa(self, keylen, exponent, flags = 0, client = 0, session = 0):
        with self.rpc(RPC_FUNC_PKEY_GENERATE_RSA, session, keylen, exponent, flags, client = client) as r:
            return PKey(self, r.unpack_uint(), UUID(bytes = r.unpack_bytes()))

    def pkey_generate_ec(self, curve, flags = 0, client = 0, session = 0):
        with self.rpc(RPC_FUNC_PKEY_GENERATE_EC, session, curve, flags, client = client) as r:
            return PKey(self, r.unpack_uint(), UUID(bytes = r.unpack_bytes()))

    def pkey_close(self, pkey):
        with self.rpc(RPC_FUNC_PKEY_CLOSE, pkey):
            return

    def pkey_delete(self, pkey):
        with self.rpc(RPC_FUNC_PKEY_DELETE, pkey):
            return

    def pkey_get_key_type(self, pkey):
        with self.rpc(RPC_FUNC_PKEY_GET_KEY_TYPE, pkey) as r:
            return HALKeyType.index[r.unpack_uint()]

    def pkey_get_key_flags(self, pkey):
        with self.rpc(RPC_FUNC_PKEY_GET_KEY_FLAGS, pkey) as r:
            return r.unpack_uint()

    def pkey_get_public_key_len(self, pkey):
        with self.rpc(RPC_FUNC_PKEY_GET_PUBLIC_KEY_LEN, pkey) as r:
            return r.unpack_uint()

    def pkey_get_public_key(self, pkey, length = None):
        if length is None:
            length = self.pkey_get_public_key_len(pkey)
        with self.rpc(RPC_FUNC_PKEY_GET_PUBLIC_KEY, pkey, length) as r:
            return r.unpack_bytes()

    def pkey_sign(self, pkey, hash = 0, data = "", length = 1024):
        with self.rpc(RPC_FUNC_PKEY_SIGN, pkey, hash, data, length) as r:
            return r.unpack_bytes()

    def pkey_verify(self, pkey, hash = 0, data = "", signature = None):
        with self.rpc(RPC_FUNC_PKEY_VERIFY, pkey, hash, data, signature):
            return

    def pkey_list(self, flags = 0, client = 0, session = 0, length = 512):
        with self.rpc(RPC_FUNC_PKEY_LIST, session, length, flags, client = client) as r:
            return tuple((HALKeyType.index[r.unpack_uint()],
                          HALCurve.index[r.unpack_uint()],
                          r.unpack_uint(),
                          UUID(bytes = r.unpack_bytes()))
                         for i in xrange(r.unpack_uint()))

    def pkey_match(self, type = 0, curve = 0, flags = 0, attributes = (),
                   previous_uuid = UUID(int = 0), length = 512, client = 0, session = 0):
        with self.rpc(RPC_FUNC_PKEY_MATCH, session, type, curve, flags,
                      attributes, length, previous_uuid, client = client) as r:
            return tuple(UUID(bytes = r.unpack_bytes())
                         for i in xrange(r.unpack_uint()))

    def pkey_set_attribute(self, pkey, attr_type, attr_value = None):
        if attr_value is None and isinstance(attr_type, Attribute):
            attr_type, attr_value = attr_type.type, attr_type.attr_value
        with self.rpc(RPC_FUNC_PKEY_SET_ATTRIBUTE, pkey, attr_type, attr_value):
            return

    def pkey_get_attribute(self, pkey, attr_type):
        with self.rpc(RPC_FUNC_PKEY_GET_ATTRIBUTE, pkey, attr_type) as r:
            return Attribute(attr_type, r.unpack_bytes())

    def pkey_delete_attribute(self, pkey, attr_type):
        with self.rpc(RPC_FUNC_PKEY_DELETE_ATTRIBUTE, pkey, attr_type):
            return

if __name__ == "__main__":

    import argparse

    def hexstr(s):
        return "".join("{:02x}".format(ord(c)) for c in s)

    parser = argparse.ArgumentParser()
    parser.add_argument("--device", default = os.getenv("CRYPTECH_RPC_CLIENT_SERIAL_DEVICE", "/dev/ttyUSB0"))
    parser.add_argument("--pin", default = "fnord")
    args = parser.parse_args()

    hsm = HSM(device = args.device)

    print "Version:", hex(hsm.get_version())

    print "Random:", hexstr(hsm.get_random(16))

    h = hsm.hash_initialize(HAL_DIGEST_ALGORITHM_SHA256)
    h.update("Hi, Mom")
    print "Hash:", hexstr(h.finalize())

    h = hsm.hash_initialize(HAL_DIGEST_ALGORITHM_SHA256, key = "secret")
    h.update("Hi, Dad")
    print "HMAC:", hexstr(h.finalize())

    print "Logging in"
    hsm.login(HAL_USER_NORMAL, args.pin)

    print "Generating key"
    k = hsm.pkey_generate_ec(HAL_CURVE_P256)
    print "PKey: {0.uuid} {0.key_type} {0.key_flags} {1}".format(k, hexstr(k.public_key))
    hsm.pkey_close(k)

    for flags in (0, HAL_KEY_FLAG_TOKEN):
        for t, c, f, u in hsm.pkey_list(flags = flags):
            print "List:", u, t, c, f

    for f in (HAL_KEY_FLAG_TOKEN, 0):
        for u in hsm.pkey_match(flags = f):
            print "Match:", u

    k = hsm.pkey_find(k.uuid)
    hsm.pkey_delete(k)

    hsm.logout()
