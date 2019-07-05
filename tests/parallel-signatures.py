#!/usr/bin/env python
#
# Copyright (c) 2016-2018, NORDUnet A/S
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
Test multiple clients and parallel RSA signatures.
"""

# This was originally going to be a complete asynchronous-capable
# version of cryptech.libhal, but that turned into a yak shaving
# exercise, so refocused on just solving the immediate task at hand,
# to wit, parallel signing tests.

import os
import sys
import uuid
import xdrlib
import socket
import logging
import datetime
import collections

import cryptech.libhal

from argparse           import ArgumentParser, ArgumentDefaultsHelpFormatter

from tornado.gen        import Return, coroutine
from tornado.ioloop     import IOLoop
from tornado.iostream   import IOStream, StreamClosedError

from Crypto.Util.asn1               import DerSequence, DerNull, DerOctetString
#---------------------------------------------------------------------------
from Crypto.Util.number             import inverse
from Crypto.PublicKey               import RSA
from Crypto.Cipher                  import AES
from Crypto.Cipher.PKCS1_v1_5       import PKCS115_Cipher
from Crypto.Signature.PKCS1_v1_5    import PKCS115_SigScheme
from Crypto.Hash.SHA256             import SHA256Hash as SHA256
from Crypto.Hash.SHA384             import SHA384Hash as SHA384
from Crypto.Hash.SHA512             import SHA512Hash as SHA512

from ecdsa                          import der as ECDSA_DER
from ecdsa.keys                     import SigningKey as ECDSA_SigningKey
from ecdsa.keys                     import VerifyingKey as ECDSA_VerifyingKey
from ecdsa.ellipticcurve            import Point
from ecdsa.curves                   import NIST256p, NIST384p, NIST521p
from ecdsa.curves                   import find_curve as ECDSA_find_curve
from ecdsa.util                     import oid_ecPublicKey

#from hashlib                    import sha256 as SHA256, sha384 as SHA384, sha512 as SHA512
#--------------------------------------------------------------------------------


try:
    import statistics
    statistics_loaded = True
except ImportError:
    statistics_loaded = False


logger = logging.getLogger(__name__)


globals().update((name, getattr(cryptech.libhal, name))
                 for name in dir(cryptech.libhal)
                 if any(name.startswith(prefix)
                        for prefix in ("HAL", "RPC", "SLIP")))


class PKey(cryptech.libhal.Handle):

    def __init__(self, hsm, handle, uuid):
        self.hsm     = hsm
        self.handle  = handle
        self.uuid    = uuid
        self.deleted = False

    @coroutine
    def close(self):
        yield self.hsm.pkey_close(self)

    @coroutine
    def delete(self):
        yield self.hsm.pkey_delete(self)
        self.deleted = True

    @coroutine
    def key_type(self):
        r = yield self.hsm.pkey_get_key_type(self)
        raise Return(r)
    @coroutine
    def sign(self, hash = 0, data = "", length = 1024):
        r = yield self.hsm.pkey_sign(self, hash = hash, data = data, length = length)
        raise Return(r)

    @coroutine
    def verify(self, data = "", signature = None):
        yield self.hsm.pkey_verify(self, data = data, signature = signature)


class ContextManagedUnpacker(xdrlib.Unpacker):
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.done()


class HSM(cryptech.libhal.HSM):

    def __init__(self,
                 sockname = os.getenv("CRYPTECH_RPC_CLIENT_SOCKET_NAME",
                                      "/tmp/.cryptech_muxd.rpc"),
                 debug_io = False):
        self.hsm = self
        self.debug_io = debug_io
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(sockname)
        self.iostream = IOStream(self.socket)

    @coroutine
    def rpc(self, code, *args, **kwargs):
        client = kwargs.get("client", 0)
        packer = xdrlib.Packer()
        packer.pack_uint(code)
        packer.pack_uint(client)
        self._pack_args(packer, args)
        packer = cryptech.libhal.slip_encode(packer.get_buffer())
        if self.debug_io:
            logger.debug("send: %s", ":".join("{:02x}".format(ord(c)) for c in packer))
        yield self.iostream.write(packer)
        while True:
            try:
                unpacker = yield self.iostream.read_until(SLIP_END)
            except StreamClosedError:
                raise HAL_ERROR_RPC_TRANSPORT()
            if self.debug_io:
                logger.debug("recv: %s", ":".join("{:02x}".format(ord(c)) for c in unpacker))
            unpacker = cryptech.libhal.slip_decode(unpacker)
            if not unpacker:
                continue
            unpacker = ContextManagedUnpacker("".join(unpacker))
            if unpacker.unpack_uint() == code:
                break
        client = unpacker.unpack_uint()
        self._raise_if_error(unpacker.unpack_uint())
        raise Return(unpacker)

    @coroutine
    def login(self, user, pin, client = 0):
        with (yield self.rpc(RPC_FUNC_LOGIN, user, pin, client = client)):
            pass

    @coroutine
    def logout(self, client = 0):
        with (yield self.rpc(RPC_FUNC_LOGOUT, client = client)):
            pass

    @coroutine
    def pkey_load(self, der, flags = 0, client = 0, session = 0):
        r = yield self.rpc(RPC_FUNC_PKEY_LOAD, session, der, flags, client = client)
        with r:
            pkey = PKey(self, r.unpack_uint(), cryptech.libhal.UUID(bytes = r.unpack_bytes()))
            logger.debug("Loaded pkey %s", pkey.uuid)
            raise Return(pkey)

    @coroutine
    def pkey_close(self, pkey):
        try:
            logger.debug("Closing pkey %s", pkey.uuid)
        except AttributeError:
            pass
        with (yield self.rpc(RPC_FUNC_PKEY_CLOSE, pkey)):
            pass

    @coroutine
    def pkey_delete(self, pkey):
        try:
            logger.debug("Deleting pkey %s", pkey.uuid)
        except AttributeError:
            pass
        with (yield self.rpc(RPC_FUNC_PKEY_DELETE, pkey)):
            pass

    @coroutine
    def pkey_sign(self, pkey, hash = 0, data = "", length = 1024):
        hash, data = 0, hash.finalize_padded(pkey)
        with (yield self.rpc(RPC_FUNC_PKEY_SIGN, pkey, hash, data, length)) as r:
            raise Return(r.unpack_bytes())


def pkcs1_hash_and_pad(text):
    return DerSequence([DerSequence([SHA256.oid, DerNull().encode()]).encode(),
                        DerOctetString(SHA256(text).digest()).encode()]).encode()


@coroutine
def client(args, k, p, q, r, m, v, h):
    while q:
        n = q.pop(0)
        logger.debug("Signing %s", n)
        t0 = datetime.datetime.now()
        s  = yield p.sign(hash = h)
        t1 = datetime.datetime.now()
        logger.debug("Signature %s: %s", n, ":".join("{:02x}".format(ord(b)) for b in s))
        if args.verify and not v.verify(args.text, SHA256, s):
            raise RuntimeError("RSA verification failed")
        r.add(t0, t1)


@coroutine
def main():
    parser = ArgumentParser(description = __doc__, formatter_class = ArgumentDefaultsHelpFormatter)
    parser.add_argument("-i", "--iterations",   default = 1000, type = int,     help = "iterations")
    parser.add_argument("-c", "--clients",      default = 4, type = int,        help = "client count")
    parser.add_argument("-k", "--key",          choices = tuple(key_table),
                                                default = "rsa_2048",           help = "key to test")
    parser.add_argument("-p", "--pin",          default = "fnord",              help = "user PIN")
    parser.add_argument("-q", "--quiet",        action = "store_true",          help = "bark less")
    parser.add_argument("-d", "--debug",        action = "store_true",          help = "bark more")
    parser.add_argument("-t", "--text",         default = "Hamsters'R'Us",      help = "plaintext to sign")
    parser.add_argument("-v", "--verify",       action = "store_true",          help = "verify signatures")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    k = key_table[args.key]
    key_type = args.key.split('_')[0]

    if key_type == "rsa":
        d = k.export_key(format = "DER", pkcs = 8)
        v = pkcs1_15.new(k)
        h = SHA256(args.text)
    else:
        sk = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256]
        vk = PreloadedKey.db[HAL_KEY_TYPE_EC_PUBLIC, HAL_CURVE_P256]
        d = sk.der
        v = vk
        #k1 = hsm.pkey_load(sk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        #k2 = hsm.pkey_load(vk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)

        #h = SHA256(args.text)
        #sig1 = yield k1.sign(hash = h)
        #sig2 = sk.sign(hamster, SHA256)
        #k1.verify(signature = sig2, hash = h)
        #k2.verify(signature = sig2, hash = h)
        #vk.verify(hamster, SHA256, sig1)
        #return

    m = pkcs1_hash_and_pad(args.text)
    q = range(args.iterations)
    r = Result(args, args.key)
    hsms = [HSM() for i in xrange(args.clients)]

    for hsm in hsms:
        yield hsm.login(HAL_USER_NORMAL, args.pin)

    for hsm in hsms:
        h = hsm.hash_initialize(HAL_DIGEST_ALGORITHM_SHA256, mixed_mode = True)
        h.update(args.text)

    pkeys = yield [hsm.pkey_load(d, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE) for hsm in hsms]

    yield [client(args, k, pkey, q, r, m, v, h) for pkey in pkeys]

    yield [pkey.delete() for pkey in pkeys]

    r.report()


class Result(object):

    def __init__(self, args, name):
        self.args = args
        self.name = name
        self.sum = datetime.timedelta(seconds = 0)
        if statistics_loaded:
            self.readings = [None] * args.iterations
        self.t0 = None
        self.t1 = None
        self.n = 0

    def add(self, t0, t1):
        if self.t0 is None:
            self.t0 = t0
        self.t1 = t1
        delta = t1 - t0
        self.sum += delta
        if statistics_loaded:
            self.readings[self.n] = delta.total_seconds()
        self.n += 1
        if not self.args.quiet:
            sys.stdout.write("\r{:4d} {}".format(self.n, delta))
            sys.stdout.flush()

    if statistics_loaded:

        @property
        def mean(self):
            return statistics.mean(self.readings)

        @property
        def median(self):
            return statistics.median(self.readings)

        @property
        def stdev(self):
            return statistics.pstdev(self.readings)

    else:

        @property
        def mean(self):
                return self.sum / self.n

    @property
    def secs_per_sig(self):
        return (self.t1 - self.t0) / self.n

    @property
    def sigs_per_sec(self):
        return self.n / (self.t1 - self.t0).total_seconds()

    @property
    def speedup(self):
        return  self.sum.total_seconds() / (self.t1 - self.t0).total_seconds()

    def report(self):
        if statistics_loaded:
            sys.stdout.write(("\r{0.name} "
                              "sigs/sec {0.sigs_per_sec} "
                              "secs/sig {0.secs_per_sig} "
                              "mean {0.mean} "
                              "median {0.median} "
                              "stdev {0.stdev} "
                              "speedup {0.speedup} "
                              "(n {0.n}, "
                              "c {0.args.clients} "
                              "t0 {0.t0} "
                              "t1 {0.t1})\n").format(self))
        else:
            sys.stdout.write(("\r{0.name} "
                              "sigs/sec {0.sigs_per_sec} "
                              "secs/sig {0.secs_per_sig} "
                              "mean {0.mean} "
                              "speedup {0.speedup} "
                              "(n {0.n}, "
                              "c {0.args.clients} "
                              "t0 {0.t0} "
                              "t1 {0.t1})\n").format(self))
        sys.stdout.flush()


key_table = collections.OrderedDict()

key_table.update(rsa_1024 = RSA.importKey('''\
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC95QlDOvlQhdCe/a7eIoX9SGPVfXfA8/62ilnF+NcwLrhxkr2R
4EVQB65+9AbxqM8Hqol6fhZzmDs48cl2tOFGJpE8iMhiFm4i6SGl2RXYaG0xi+lJ
FrXXCLFQovIEMuukBE129wra1xIB72tYR14lu8REX+Mhpbuz44M1jlCrlQIDAQAB
AoGAeU928l8bZIiH9PnlG318kYkMVhd4SGjXQK/zl9hXSC2goNV4i1d1kCHIJMwq
H3mTALe+aeVg3GnU85Tq+g2llzogoyXl8q902KbvImrM/XSbsue9/oj0OSgw+jKB
faFzX6FxAtNV5pmU9QiwauBIl/3yPCF9ifim5zg+pWCqLaECQQD59Z/R6TrTHxp6
w2vH4CJyP5KORcf+eMa50SAriMVBXsJzsBiLLVxKIZfWbQn9gytJqJZKmIHezZQm
dyam84fpAkEAwnvSF27RhxLXE037+t7k5MZti6BfNTeUBrwffteepL6qax9HK+h9
IQZ1vfNIqjZm8i7kQQyy4L8tRnk8mjZmzQJBAIUwfXWTilW+yBRMFx1M7+3itAv9
YODWqEWRCkxIN5tqi8CrP5jBleCmX8rRFTaxcxpvq42aD/GRp3SLntvs/ikCQCSg
GOKc1gyv+Z0DFK8cBtMmoz6mRwfInbHe/7dtd8zis0lVLJwSPm5Xvxi0ljyn3h9B
wW6Wq6Ezn50j+8u27wkCQQCcIFE01BDAdtFHtTJ3aaEM9IdMCYrcJ0I/Y0NTE2M6
lsTSiPyQjc4dQQJxFduvWHLx28bx+l7FTav7FaKntCJo
-----END RSA PRIVATE KEY-----
'''))

key_table.update(rsa_2048 = RSA.importKey('''\
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsbvq6syhDXD/OMVAuLoMceGQLUIiezfShVqFfyMqADjqhFRW
Wbonn0XV9ZkypU4Ib9n6PtLATNaefhpsUlI4s+20YTlQ7GiwJ9p97/N1o1u060ja
4LdqhfYtn8GZX+JAfa5NqpmLKCJ58XJ3q28MPLRwYp5yKckjkzchZHFyjs1W7r5a
JfeJ/vsQusX3klmCehJ1jxSHPh8o6lTjFMnBK8t360YTu0UGK/RUcEAYO7l7FWjd
8PjZfawXIrOAhCLkVvDFfpsl2oyFIL9d1QE87WdyyZXAtWLs62gnX+kiBq9gUhu5
GsgcQifHBcRiGZfH0TRIMgIsSjsorzHqJ9uoQwIDAQABAoIBAGqzx5/5A8NfEEpT
2bxNLcV8xqL1LmBNLh0TMEwYn1GM2fZh74lkwf7T3VTaCVbGlzgXZC4tNneq7XIF
iPyPEi2rSnyH/XZAj2kNukfBIOHW37HVhloco14TYmajwuGWomMRrtz521pYAF+c
+g042N7k8Qez2hQOBkaOdYSouz7RNdJUGUocRhcSkh+QZTBwtQxrkuhhHN+zkIri
+Q09hF2hAliHrh6mow8ci0gRsXnZzsdJfTX8CasHWTIll4gfrvWnUY7iYqB6ynRU
YN+7IgQXMUFLziIlH1qN+DlEYdznsgAPSS3JdTWh0cvjiO8wTFAnOIdsj+BpKoDB
PK2zzDkCgYEA3TP8h4Ds/y1tDijE3Sarrg0vWuY97sJmAla4qFHH4hscZ84NDzTM
I/ohLPJgpeR2MaBqZmVk9UFrd3rdt3/lX6kSO7Kffa9rVgfOB4CqJ4joso3j0qY8
V/iVBcDcD1h4aXCRX2tMJICUTgVU/N8/2wBEElcOUjZHGlcHmbHndlUCgYEAzbFm
ttPuIHrYHkmOm/DjYB65+WD8gfPMdeUbnx+yIt5xwimIbq1qWzl4++goTAAyaU/7
qM9IfveRue0B7yjnPa8fjN+CcXMGM6a3BIqeIv1icfgjHxlt7D+64FpENWXHvFE0
MhRliINfkTHm+U4+1s0045a+bLdTbfVly1gATDcCgYEAyOaoWmFL3k7hl1SLx9eR
YVj0Q3iNk0XX5BPjTmxIQCEjYVwRHFh1d897Rhk0kja26kepmypH0UADXNaofDqa
lpE10CZhGIOz1sTr6ICBCbscrN6VpgH5GGTa5AjPVNijNBBa1/DZjOWCzIGnOKuC
kWLicE3E4gIN/exBKOQdNqkCgYEAjA5PMg38BoGexoCvad8L81b4qqUvSg0HGv91
X1Plp3hvXRWKoFHUKWlox528UoOPz8V2ReteIZXQ1BhdSMtBKO8lPHa0CyuW/XR3
CdCY/Jorfg7HW1WlU0fRpxHPf8xdxAxGzhK1T86kM+kWrIpqnzf62zy5TK1HUYfW
WC8DhOECgYBzU8hIA0PU7aRPUs0o9MO9XcvVPvdX6UOKdNb9CnBMudS/chKHJUYP
d0fFAiVaRX0JMQ0RSrenxCqfWVtW3T3wFYNHB/IFRIUT3I44wwXJTNOeoi3FDTMx
EQfc0UFoFHyc3mYEKR4zHheqQG5OFBN89LqG3S+O69vc1qwCvNKL+Q==
-----END RSA PRIVATE KEY-----
'''))

key_table.update(rsa_4096 = RSA.importKey('''\
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
'''))

key_table.update(ecc_256 = '''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDLIUDl4ZL62cMVoDekHxuUKHQUMUMXvh2tJTGj4vPmwoAoGCCqGSM49
AwEHoUQDQgAEX8IPZV1M/i6OYZg2LCxwgHQtMrIt57YqMrTEgI+Db3hz1Tdpsbv1
v7Yiq/Qd6uJ0E14f/mir94tTw1ezl/CzBg==
-----END EC PRIVATE KEY-----''')

key_table.update(ecc_384 = '''-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCSIxIaAYAEMtHiirDlGtihnUSRjAr2enqW24x8JXQLqmY4glBFxpy4
bls3mJ/C0FagBwYFK4EEACKhZANiAARnEiGXGAdjWqUVgvMwDpTYpQRuFpMbVuHA
TjC0LjsLMQ+IpdJUMBSys4lp82AJOg4+pmxRsbsSO0IiaMFcS3FzGc6KBvFNXqfh
HkkzWsLk/S5G6FG3ZF1JaSMpoj2FtAQ=
-----END EC PRIVATE KEY-----''')

key_table.update(ecc_521 = '''-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBXGqrYLTV96IGy84CzhCl/DUzZ3AxqD2dIZ6e80FSdTKK+A92d6KF
xuQP/8KpRnSo35Q2mH6W+MwODayW2WpI22egBwYFK4EEACOhgYkDgYYABAB3e4ux
kgEyL6Ib9hgewTSs1AK0/hQqT6AOVySY6tLl9PxI1Lwx2zMniNq2AcjUaF3+AVDX
ayCMXD1lQY7FpPvqQQAe1RFfobtvCgddV+3L573bebeiabh3xEIHtTT7fo2rXUZ2
0cdSS0nkUiSo2hXrEUJf6yN5x0+RB8YtfqEtvzDzOA==
-----END EC PRIVATE KEY-----''')

class PreloadedKey(object):
    """
    Keys for preload tests, here at the end because they're large.
    These are now in PKCS #8 format, which gives us a single,
    consistent, self-identifying private key format.  See tools
    like "openssl pkcs8" if you need to convert from some other format
    (eg, PKCS #1 or secg).
    """

    db = {}

    def __init__(self, keytype, fn2, obj, der, keylen = None, curve = HAL_CURVE_NONE):
        self.keytype = keytype
        self.fn2     = fn2
        self.obj     = obj
        self.der     = der
        self.keylen  = keylen
        self.curve   = curve
        self.db[keytype, fn2] = self

class PreloadedRSAKey(PreloadedKey):

    @classmethod
    def importKey(cls, keylen, pem):
        k1 = RSA.importKey(pem)
        k2 = k1.publickey()
        cls(HAL_KEY_TYPE_RSA_PRIVATE, keylen,
            k1, k1.exportKey(format = "DER", pkcs = 8), keylen = keylen)
        cls(HAL_KEY_TYPE_RSA_PUBLIC,  keylen,
            k2, k2.exportKey(format = "DER"          ), keylen = keylen)

    def sign(self, text, hash):
        return PKCS115_SigScheme(self.obj).sign(hash(text))

    def verify(self, text, hash, signature):
        return PKCS115_SigScheme(self.obj).verify(hash(text), signature)

class PreloadedECKey(PreloadedKey):

    @staticmethod
    def _check(condition):
        if not condition:
            raise ECDSA_DER.UnexpectedDER()

    @classmethod
    def importKey(cls, curve, pem):
        der = ECDSA_DER.unpem(pem)
        car, cdr = ECDSA_DER.remove_sequence(der)
        cls._check(cdr == "")
        version, cdr = ECDSA_DER.remove_integer(car)
        cls._check(version == 0)
        algid, pkinfo = ECDSA_DER.remove_sequence(cdr)
        oid, cdr = ECDSA_DER.remove_object(algid)
        cls._check(oid == oid_ecPublicKey)
        oid, cdr = ECDSA_DER.remove_object(cdr)
        sk_curve = ECDSA_find_curve(oid)
        cls._check(cdr == "")
        car, cdr = ECDSA_DER.remove_octet_string(pkinfo)
        cls._check(cdr == "")
        car, cdr = ECDSA_DER.remove_sequence(car)
        cls._check(cdr == "")
        version, cdr = ECDSA_DER.remove_integer(car)
        cls._check(version == 1)
        privkey, cdr = ECDSA_DER.remove_octet_string(cdr)
        k1 = ECDSA_SigningKey.from_string(privkey, sk_curve)
        k2 = k1.get_verifying_key()
        cls(HAL_KEY_TYPE_EC_PRIVATE, curve, k1, der,         curve = curve)
        cls(HAL_KEY_TYPE_EC_PUBLIC,  curve, k2, k2.to_der(), curve = curve)

    def sign(self, text, hash):
        return self.obj.sign(text, hashfunc = hash)

    def verify(self, text, hash, signature):
        return self.obj.verify(signature, text, hashfunc = hash)


# openssl genrsa 1024
PreloadedRSAKey.importKey(1024, '''\
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL3lCUM6+VCF0J79
rt4ihf1IY9V9d8Dz/raKWcX41zAuuHGSvZHgRVAHrn70BvGozweqiXp+FnOYOzjx
yXa04UYmkTyIyGIWbiLpIaXZFdhobTGL6UkWtdcIsVCi8gQy66QETXb3CtrXEgHv
a1hHXiW7xERf4yGlu7PjgzWOUKuVAgMBAAECgYB5T3byXxtkiIf0+eUbfXyRiQxW
F3hIaNdAr/OX2FdILaCg1XiLV3WQIcgkzCofeZMAt75p5WDcadTzlOr6DaWXOiCj
JeXyr3TYpu8iasz9dJuy573+iPQ5KDD6MoF9oXNfoXEC01XmmZT1CLBq4EiX/fI8
IX2J+KbnOD6lYKotoQJBAPn1n9HpOtMfGnrDa8fgInI/ko5Fx/54xrnRICuIxUFe
wnOwGIstXEohl9ZtCf2DK0molkqYgd7NlCZ3Jqbzh+kCQQDCe9IXbtGHEtcTTfv6
3uTkxm2LoF81N5QGvB9+156kvqprH0cr6H0hBnW980iqNmbyLuRBDLLgvy1GeTya
NmbNAkEAhTB9dZOKVb7IFEwXHUzv7eK0C/1g4NaoRZEKTEg3m2qLwKs/mMGV4KZf
ytEVNrFzGm+rjZoP8ZGndIue2+z+KQJAJKAY4pzWDK/5nQMUrxwG0yajPqZHB8id
sd7/t213zOKzSVUsnBI+ble/GLSWPKfeH0HBbparoTOfnSP7y7bvCQJBAJwgUTTU
EMB20Ue1MndpoQz0h0wJitwnQj9jQ1MTYzqWxNKI/JCNzh1BAnEV269YcvHbxvH6
XsVNq/sVoqe0Img=
-----END PRIVATE KEY-----
''')

# openssl genrsa 2048
PreloadedRSAKey.importKey(2048, '''\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCxu+rqzKENcP84
xUC4ugxx4ZAtQiJ7N9KFWoV/IyoAOOqEVFZZuiefRdX1mTKlTghv2fo+0sBM1p5+
GmxSUjiz7bRhOVDsaLAn2n3v83WjW7TrSNrgt2qF9i2fwZlf4kB9rk2qmYsoInnx
cnerbww8tHBinnIpySOTNyFkcXKOzVbuvlol94n++xC6xfeSWYJ6EnWPFIc+Hyjq
VOMUycEry3frRhO7RQYr9FRwQBg7uXsVaN3w+Nl9rBcis4CEIuRW8MV+myXajIUg
v13VATztZ3LJlcC1YuzraCdf6SIGr2BSG7kayBxCJ8cFxGIZl8fRNEgyAixKOyiv
Meon26hDAgMBAAECggEAarPHn/kDw18QSlPZvE0txXzGovUuYE0uHRMwTBifUYzZ
9mHviWTB/tPdVNoJVsaXOBdkLi02d6rtcgWI/I8SLatKfIf9dkCPaQ26R8Eg4dbf
sdWGWhyjXhNiZqPC4ZaiYxGu3PnbWlgAX5z6DTjY3uTxB7PaFA4GRo51hKi7PtE1
0lQZShxGFxKSH5BlMHC1DGuS6GEc37OQiuL5DT2EXaECWIeuHqajDxyLSBGxednO
x0l9NfwJqwdZMiWXiB+u9adRjuJioHrKdFRg37siBBcxQUvOIiUfWo34OURh3Oey
AA9JLcl1NaHRy+OI7zBMUCc4h2yP4GkqgME8rbPMOQKBgQDdM/yHgOz/LW0OKMTd
JquuDS9a5j3uwmYCVrioUcfiGxxnzg0PNMwj+iEs8mCl5HYxoGpmZWT1QWt3et23
f+VfqRI7sp99r2tWB84HgKoniOiyjePSpjxX+JUFwNwPWHhpcJFfa0wkgJROBVT8
3z/bAEQSVw5SNkcaVweZsed2VQKBgQDNsWa20+4getgeSY6b8ONgHrn5YPyB88x1
5RufH7Ii3nHCKYhurWpbOXj76ChMADJpT/uoz0h+95G57QHvKOc9rx+M34JxcwYz
prcEip4i/WJx+CMfGW3sP7rgWkQ1Zce8UTQyFGWIg1+RMeb5Tj7WzTTjlr5st1Nt
9WXLWABMNwKBgQDI5qhaYUveTuGXVIvH15FhWPRDeI2TRdfkE+NObEhAISNhXBEc
WHV3z3tGGTSSNrbqR6mbKkfRQANc1qh8OpqWkTXQJmEYg7PWxOvogIEJuxys3pWm
AfkYZNrkCM9U2KM0EFrX8NmM5YLMgac4q4KRYuJwTcTiAg397EEo5B02qQKBgQCM
Dk8yDfwGgZ7GgK9p3wvzVviqpS9KDQca/3VfU+WneG9dFYqgUdQpaWjHnbxSg4/P
xXZF614hldDUGF1Iy0Eo7yU8drQLK5b9dHcJ0Jj8mit+DsdbVaVTR9GnEc9/zF3E
DEbOErVPzqQz6RasimqfN/rbPLlMrUdRh9ZYLwOE4QKBgHNTyEgDQ9TtpE9SzSj0
w71dy9U+91fpQ4p01v0KcEy51L9yEoclRg93R8UCJVpFfQkxDRFKt6fEKp9ZW1bd
PfAVg0cH8gVEhRPcjjjDBclM056iLcUNMzERB9zRQWgUfJzeZgQpHjMeF6pAbk4U
E3z0uobdL47r29zWrAK80ov5
-----END PRIVATE KEY-----
''')

# openssl genrsa 4096
PreloadedRSAKey.importKey(4096, '''\
-----BEGIN PRIVATE KEY-----
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
w3l5Zt78ppncQDSUdGbI5D75aBTqOg==
-----END PRIVATE KEY-----
''')

# openssl ecparam -genkey -name prime256v1 | openssl ec
PreloadedECKey.importKey(HAL_CURVE_P256, '''\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8GtWEPWIUXZ7zA+Q
9/g3XTfyJHzE+CS78JU5PyVxLO2hRANCAATeYHkGY3kVrh9XvguwNYikFTGS0+pg
YnpY4GuM+zUdaQ1Tskc7epj3LL4JcVI9vz0ZZCBvnAu00+fhBgyP4pFM
-----END PRIVATE KEY-----
''')

# openssl ecparam -genkey -name secp384r1 | openssl ec
PreloadedECKey.importKey(HAL_CURVE_P384, '''\
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCVGo35Hbrf3Iys7mWR
Im5yjg+6vPIgzbp2jCbDyszBo+wTxmQambG4g8yocp4wM6+hZANiAATYwa+M8T8j
sNHKmMZTvPPflUIfrjuZZo1D3kkkmN4r6cTNctjaeRdAfD0X40l4yPnGIP9ParuK
VVl1y0TdQ7BS3g/Gj/LP33HDESP8gFDIKFCWSDX0uhmy+HsGsPwgNoY=
-----END PRIVATE KEY-----
''')

# openssl ecparam -genkey -name secp521r1 | openssl ec
PreloadedECKey.importKey(HAL_CURVE_P521, '''\
-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBtf+LKhJNQEJRFQ2c
GQPcviwfp9IKSnD5EFTqAPtv7/+t2FtmdHHP/fWIlZ7jcC5N9dWy6bKGu3+FqwgZ
AYLpsqihgYkDgYYABADdfcUeP0oAZQ5308v5ijcg4hePvhvVi+QKcrwmE9kirXCF
oYN1tzPmXZmw8lNJenrbwaNzopJR84LBHnomGPogAQGF0aRk0jE8w1j1oMfrrzV6
vCWnkh7pyzsDnrLU1HrkWeqwihzwMzYJgFzToDH+fCh7nrBFZZZ9P9gPYMlSM5UM
eA==
-----END PRIVATE KEY-----
''')

if __name__ == "__main__":
    IOLoop.current().run_sync(main)
