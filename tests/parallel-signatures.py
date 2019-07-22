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
import json

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
        if(hash):
            hash, data = 0, hash.finalize_padded(pkey)
        with (yield self.rpc(RPC_FUNC_PKEY_SIGN, pkey, hash, data, length)) as r:
            raise Return(r.unpack_bytes())


def pkcs1_hash_and_pad(text):
    return DerSequence([DerSequence([SHA256.oid, DerNull().encode()]).encode(),
                        DerOctetString(SHA256(text).digest()).encode()]).encode()


@coroutine
def client_ec(verify, pyhash, pkey, q, r, m, v, h):
    while q:
        n = q.pop(0)
        logger.debug("Signing %s", n)
        t0 = datetime.datetime.now()
        s  = yield pkey.sign(hash = h)
        t1 = datetime.datetime.now()
        logger.debug("Signature %s: %s", n, ":".join("{:02x}".format(ord(b)) for b in s))
        if verify and not v.verify(m, pyhash, s):
            raise RuntimeError("EC verification failed")
        r.add(t0, t1)

@coroutine
def client_rsa(verify, k, pkey, q, r, m, v, h):
    while q:
        n = q.pop(0)
        logger.debug("Signing %s", n)
        t0 = datetime.datetime.now()
        s  = yield pkey.sign(data = m)
        t1 = datetime.datetime.now()
        logger.debug("Signature %s: %s", n, ":".join("{:02x}".format(ord(b)) for b in s))
        if verify and not v.verify(h, s):
            raise RuntimeError("RSA verification failed")
        r.add(t0, t1)

@coroutine
def load_sign(iterations, clients, key, quiet, text, verify, output, file, hsms):
    k = key_table[key]
    key_type = key.split('_')[0]
    q = range(iterations)
    r = Result(iterations, clients, quiet, key, output, file)

    if key_type == "rsa":
        d = k.exportKey(format = "DER", pkcs = 8)
        v = PKCS115_SigScheme(k)
        m = pkcs1_hash_and_pad(text)
        h = SHA256(text)
        pkeys = yield [hsm.pkey_load(d, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE) for hsm in hsms]
        yield [client_rsa(verify, k, pkey, q, r, m, v, h) for pkey in pkeys]
    else:
        key_size = key.split('_')[1]
        if key_size == "521":
            alg = HAL_DIGEST_ALGORITHM_SHA512
            pyhash = SHA512
            curve = HAL_CURVE_P521
        else:
            curve = eval('HAL_CURVE_P' + key_size)
            alg = eval('HAL_DIGEST_ALGORITHM_SHA' + key_size)
            pyhash = eval('SHA' + key_size)
        d = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, curve].der
        v = PreloadedKey.db[HAL_KEY_TYPE_EC_PUBLIC, curve]
        m = text
        for hsm in hsms:
            h = hsm.hash_initialize(alg, mixed_mode = True)
            h.update(m)

        pkeys = yield [hsm.pkey_load(d, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE) for hsm in hsms]
        yield [client_ec(verify, pyhash, pkey, q, r, m, v, h) for pkey in pkeys]

    yield [pkey.delete() for pkey in pkeys]

    yield r.report()

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
    parser.add_argument("-l", "--loop",         action = "store_true",          help = "loop from 1..n clients, 1..n iteration")
    parser.add_argument("-o", "--output",       choices=["str", "json", "json_pretty", "csv"], default = "str", help = "Output format of output 'str, json, csv'")
    parser.add_argument("-f", "--file",         default = "",                 help = "Save result to file location")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.file != "":
        with open(args.file, "w") as outfile:
            outfile.write('')

    hsms = [HSM() for i in xrange(args.clients)]

    for hsm in hsms:
        yield hsm.login(HAL_USER_NORMAL, args.pin)

    if args.loop:
        for i in range(0, args.iterations):
            for c in range(0, args.clients):
                if args.key == "all":
                    for key in key_table:
                        if key != "all":
                            yield load_sign((i + 1), (c + 1), key, args.quiet, args.text, args.verify, args.output, args.file, hsms)
                else:
                    yield load_sign((i + 1), (c + 1), args.key, args.quiet, args.text, args.verify, args.output, args.file, hsms)
    else:
        if args.key == "all":
            for key in key_table:
                if key != "all":
                    yield load_sign(args.iterations, args.clients, key, args.quiet, args.text, args.verify, args.output, args.file, hsms)
        else:
            yield load_sign(args.iterations, args.clients, args.key, args.quiet, args.text, args.verify, args.output, args.file, hsms)

    if args.file != "" and (args.output == "json" or args.output == "json_pretty"):
        with open(args.file, "r") as outfile:
            #converto to JSON object, remove last two chars ",\n"
            file_contents = "[\n" + outfile.read()[:-2] + "\n]"
        with open(args.file, "w") as outfile:
            outfile.write(file_contents)

def datetime_convert(o):
    if isinstance(o, datetime.timedelta):
        return o.__str__()

class Result(object):

    def __init__(self, iterations, clients, quiet, name, output, file):
        self.name = name
        self.sum = datetime.timedelta(seconds = 0)
        if statistics_loaded:
            self.readings = [None] * iterations
        self.t0 = None
        self.t1 = None
        self.n = 0
        self.clients = clients
        self.quiet = quiet
        self.output = output
        self.file = file

    def add(self, t0, t1):
        if self.t0 is None:
            self.t0 = t0
        self.t1 = t1
        delta = t1 - t0
        self.sum += delta
        if statistics_loaded:
            self.readings[self.n] = delta.total_seconds()
        self.n += 1
        if not self.quiet:
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
        return self.sum.total_seconds() / (self.t1 - self.t0).total_seconds()

    @property
    def toJSON(self):
        if statistics_loaded:
            return {
                "name" : self.name,
                "sigs_per_sec" : self.sigs_per_sec.__str__(),
                "secs_per_sig" : self.secs_per_sig.__str__(),
                "mean" : self.mean,
                "median" : self.median,
                "stdev" : self.stdev,
                "speedup" : self.speedup.__str__(),
                "n" : self.n,
                "clients" : self.clients,
                "t0" : self.t0.__str__(),
                "t1" : self.t1.__str__()
            }
        else:
            return {
                "name" : self.name,
                "sigs_per_sec" : self.sigs_per_sec.__str__(),
                "secs_per_sig" : self.secs_per_sig.__str__(),
                "mean" : self.mean,
                "speedup" : self.speedup.__str__(),
                "n" : self.n,
                "clients" : self.clients,
                "t0" : self.t0.__str__(),
                "t1" : self.t1.__str__()
            }

    @property
    def toCSV(self):
        if statistics_loaded:
            return ("{0.name}, "
                    "{0.sigs_per_sec}, "
                    "{0.secs_per_sig}, "
                    "{0.mean}, "
                    "{0.median}, "
                    "{0.stdev}, "
                    "{0.speedup}, "
                    "{0.n}, "
                    "{0.clients}, "
                    "{0.t0}, "
                    "{0.t1}").format(self)
        else:
            return ("{0.name}, "
                    "{0.sigs_per_sec}, "
                    "{0.secs_per_sig}, "
                    "{0.mean}, "
                    "{0.speedup}, "
                    "{0.n}, "
                    "{0.clients}, "
                    "{0.t0}, "
                    "{0.t1}").format(self)

    def __str__(self):
        if statistics_loaded:
            return ("{0.name} "
                "sigs/sec {0.sigs_per_sec} "
                "secs/sig {0.secs_per_sig} "
                "mean {0.mean} "
                "median {0.median} "
                "stdev {0.stdev} "
                "speedup {0.speedup} "
                "(n {0.n}, "
                "c {0.clients} "
                "t0 {0.t0} "
                "t1 {0.t1})").format(self)
        else:
            return ("{0.name} "
                "sigs/sec {0.sigs_per_sec} "
                "secs/sig {0.secs_per_sig} "
                "mean {0.mean} "
                "speedup {0.speedup} "
                "(n {0.n}, "
                "c {0.args.clients} "
                "t0 {0.t0} "
                "t1 {0.t1})").format(self)

    @coroutine
    def report(self):
        if self.output == "str":
            result = str(self)
        elif self.output == "json":
            result = json.dumps(self.toJSON, sort_keys = True)
            result = result + ','
        elif self.output == "json_pretty":
            result = json.dumps(self.toJSON, sort_keys = True, indent = 4)
            result = result + ','
        elif self.output == "csv":
            result = self.toCSV

        sys.stdout.write('\r' + result + '\n')
        sys.stdout.flush()

        if self.file != "":
            with open(self.file, "a") as outfile:
                outfile.write(result + '\n')

key_table = collections.OrderedDict()

key_table.update(all = "")

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
MIIJKAIBAAKCAgEAzWpYSQt+DrUNI+EJT/ko92wM2POfFnmm3Kc34nmuK6sez0DJ
r9Vib9R5K46RNgqcUdAodjU6cy3/MZA53SqP7RwR/LQtWmK2a+T4iey2vQZ0iCDA
2NI4gjgmCAjZnOD/m5yUXjCig/wJ8pGXolg8oHnvdeLg1joIOSF9OudLrI6aJnDg
OfdegzmCWXmWl7TXrqHVIWZhZZF7qQZRso6ZQ1/8mjpvVD0drASBxMnIzvpe4ynr
Y2NB807X/D5bbScp292ZKTNf5unPN1SsFy5ymzfLZrfNksYef6xPXcVr6OiObi49
De8e11aNPj6fgLzzqAu1rjjrDkgvXx5G7gPJXq1aq6uxB2cKMrRS+ivmyC8vQlzP
lQwW20oYeeOfCg7ddNAJcu3jNTuNJaZdhc9szpVhV8DXZoXe/RzUNjZH7wUqueHy
fpbLwS+h3McJqrbWFdCQBivZnoI05cF2JIHEeR3S0Gyo2/IheNeFX2Tt8oDnHY4a
olRHiR5CMdM8UoGSxR9Y12fZ9dcqdCH3d6wDAsBDHTCE8ZIwFwhW6iA+g54YE3X7
BlsgWr60poCDgH+CJjh0VDVxqL7r+w76sD9WAQMa7Gb+Mp2XCYnIZPXTrsmwVbZ9
s5vFXUEODYom6qBlbZB8gyZzee5Skc1jx2fnmqxRtflA4W3xVAQFof2rFiUCAwEA
AQKCAgBxhQXJSFqf0hqy61h0I+Qp6EKpWuleSFiYtKjDti803tql+s37KFfAKZHV
KnLBhNeitwDFYuEsag0P3P69ZRopFUwzdXdi7g6WTfG0d2b9y6V23XL14Cduf400
/38TnZxk6QFtlD8b5ZuxvBgqlczbeseFRJ6whV2qBQHqHYzKjfxOpi6kmjpXFt8c
h39b04smbTUVwjitIttOK7nWjcvRWiiFKyn/Sc8uE0eL81/QUrlBnRcC1AXMapQe
SG/KQMx3P123UTb8q9XiZB6+qOKZORplZ8pqBKcyM42g6suZ6XtdFJyVKMLIioKA
FaecQ8/73IzI/ZeZSvcy/85/FwSfGjHD7C7vL9kfg77no+IvHYlBYiIqtTddpQH5
LGJAJnOGtk047/OjTmL8QyylvDAv8jBeZZdbOX7L+8jk5DbHmfUcDjvBS9g+Fbfk
jDurphrp1dHn/YgaA27NZs87TPWX1aVPiOlXEhO9SHHiiKCHDpBzV1gW/eiho33s
+uEr57ZoakzonN/zNb7KqHUO/ZGwMg+V9bVIgThqbdgmxNz7JFz14CN79yPmW5QT
1P1v7a6xWaZTALe2HGvy0B+iRzhLpay1tI4O/omPj9vUzVJwGHztVt0RddcmA9wV
Y3qglRNl+YvNlm6BUn8KwPIqki8JoioA8J1EQ5mz/K0fbrzcOQKCAQEA8TCqq0pb
mfxtsf42zhsSUw1VdcCIG0IYcSWxIiCfujryAQX1tmstZeRchlykXmdO+JDcpvMy
BKBD7188JEWjCX1IRRtHxTJ5WG+pE8sNPLNL8eZVZ+CEbNjVk4dtWGLwyNm+rQkM
NmOlm+7ZHdezBXljZOeqZbdsTSDQcGYG8JxlvLpAN60pjIGvTdTrdnksMhB4PK+l
7KtyEVDWXU/VT6kqhP3Ri1doHv/81BplgfjEJM8ZxmasfP4SlJ1olKqsHMFSrclj
ZCAemKEexVyzg8cHm9ghj6MLQZe3gs94V6h8I2ifrBBNHMrZgYg2Db0GeyYrr+kZ
GDjT0DZp0jgyfwKCAQEA2gdTclmrfAU/67ziOJbjkMgfhBdteE1BbJDNUca0zB6q
Ju4BwNgt0cxHMbltgE2/8hWP95HIaQdh1mIgwSK93MxRbaAvAQfF3muJxvMR5Mru
DejE+IEK9eZetgkNHGWyfiFzBWHda/Z9PQkqYtRfop5qFBVAPZ4YzR5hT0j64eDQ
N/z9C0ZB6RL9EcXJgEYgGI3wP8Qsrw3JRBQN0SCVRmrEJm4WIXs+CEHOk56/VbPM
v82uwbHVghS0U9bEZvNoeq7ZQjS2tRXXRJeOgQyCNvYy670T0KvQZoDb59EbEDSz
eQZS1J7rDEBHW+VwRSJA8noMEgZdEv8AxbEF2CddWwKCAQAMwH71iXvoW1FNbNxm
70V7wKO5ExHfJxJ1wQFphYIMbZtn9HG2UFpZHcbKj9Fc8GdbewU/inIljnepC0b5
v/jLwqT0imm0AmQqCdVNp5mukOg+BOiVEmjN/HTmVO2yE6EZbXHIYkcUBRa3dNxj
2IitjGp15k27DQSb21VJ7AsH46z5WnuUtgIRXLXxDoXYgLWWfApvYvYJ2lKwma6L
xnHHwXDvESBoFpn5sZ0jdbXSNl3geFarh7gs753534ys940cBBij+ZbYr14Owc4H
r0wKdpZvZfD4UC2DLUtVjjSVpeHSWXC/vyjkkdEIKTR6a3kRP8ZliZR7FF4Wjxnv
NGtvAoIBAEu5g6gRsNewUxUjU0boUT115ExSfrjrzC9S05z1cNH8TIic3YsHClL1
qjyA9KE9X89K4efQgFTKNZbqGgo6cMsBQ77ZhbnL41Nu8jlhLvPR74BxOgg9eXsS
eg6rchxMzgO0xmg2J1taDwFl74zHyjeG4bz77IX6JQ8I4C9TX5+YH3lyqsiBrF6x
M6g6k9Ozh24/zhO3pPVfymmUtX/O20nLxzi5v4H9dfwULxVia33upsxvOaUYiNlX
K5J641gGbmE93UN7X4HhhhTStrHnkEpalDEASKOPKSCQ3M/U9ptYUoVURuyGDYkB
wkcOl0HLtdcBwLN59lWkr7X519fNREUCggEBAMk39k+shD2DW8ubE/LgoforwfT2
558FPxpZ+pGwMHL3ZnLuQuiROyPyQZj/ZmmLAa2TPrwS/ssln46Y2KesejWK/0Hq
8SaFLhOjacF8u5IOOKBZvx+HOT6ctRNBVyzt9A8wu0DE6nzc5HQpm9TMXrOLuZ0L
u22yFikwoIgYpU6hBdbg1mnirZS/ZyqJV9gWB6ZYyUAUGdgBqL6euSAAqBp93qz8
sQLesqTufT1mVZd/ndLyvjDJjNKUE0w1g/1xNtg6N5aM+7pc/DwE/s+EtCxc/858
dQYLBHIPcw6e0FdL3nTs44BpAqcK28N5eWbe/KaZ3EA0lHRmyOQ++WgU6jo=
-----END RSA PRIVATE KEY-----
'''))

#Note below are used as a reference for arg parse
key_table.update(ec_256 = "256")

key_table.update(ec_384 = "384")

key_table.update(ec_521 = "521")

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
