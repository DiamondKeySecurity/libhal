#!/usr/bin/env python

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
LibHAL unit tests, using libhal.py and the Python unit_test framework.
"""

# There's some overlap between these tests and the PKCS #11 unit tests,
# because in many cases we're testing the same functionality, just via
# different APIs.

import unittest
import datetime
import logging
import sys

from struct import pack, unpack

from libhal import *

try:
    from Crypto.Util.number             import inverse
    from Crypto.PublicKey               import RSA
    from Crypto.Cipher                  import AES
    from Crypto.Cipher.PKCS1_v1_5       import PKCS115_Cipher
    from Crypto.Signature.PKCS1_v1_5    import PKCS115_SigScheme
    from Crypto.Hash.SHA256             import SHA256Hash as SHA256
    from Crypto.Hash.SHA384             import SHA384Hash as SHA384
    from Crypto.Hash.SHA512             import SHA512Hash as SHA512
    pycrypto_loaded = True
except ImportError:
    pycrypto_loaded = False


try:
    from ecdsa                          import der as ECDSA_DER
    from ecdsa.keys                     import SigningKey as ECDSA_SigningKey
    from ecdsa.keys                     import VerifyingKey as ECDSA_VerifyingKey
    from ecdsa.ellipticcurve            import Point
    from ecdsa.curves                   import NIST256p, NIST384p, NIST521p
    from ecdsa.curves                   import find_curve as ECDSA_find_curve
    from ecdsa.util                     import oid_ecPublicKey
    if not pycrypto_loaded:
        from hashlib                    import sha256 as SHA256, sha384 as SHA384, sha512 as SHA512
    ecdsa_loaded = True
except ImportError:
    ecdsa_loaded = False


logger = logging.getLogger("unit-tests")


def main():
    from sys import argv
    global args
    args = parse_arguments(argv[1:])
    argv = argv[:1] + args.only_test
    logging.basicConfig(level   = logging.DEBUG if args.debug else logging.INFO,
                        datefmt = "%Y-%m-%d %H:%M:%S",
                        format  = "%(asctime)-15s %(name)s[%(process)d]:%(levelname)s: %(message)s",)
    unittest.main(verbosity  = 1 if args.quiet else 2,
                  argv       = argv,
                  catchbreak = True,
                  testRunner = TextTestRunner)

def parse_arguments(argv = ()):
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    parser = ArgumentParser(description = __doc__, formatter_class = ArgumentDefaultsHelpFormatter)
    parser.add_argument("--quiet",      action = "store_true",          help = "suppress chatter")
    parser.add_argument("--debug",      action = "store_true",          help = "debug-level logging")
    parser.add_argument("--io-log",     action = "store_true",          help = "log HSM I/O stream")
    parser.add_argument("--wheel-pin",  default = "fnord",              help = "PIN for wheel user")
    parser.add_argument("--so-pin",     default = "fnord",              help = "PIN for security officer")
    parser.add_argument("--user-pin",   default = "fnord",              help = "PIN for normal user")
    parser.add_argument("--all-tests",  action = "store_true",          help = "enable tests usually skipped")
    parser.add_argument("--only-test",  default = [], nargs = "+",      help = "only run tests named here")
    return parser.parse_args(argv)

args = parse_arguments()
hsm  = None

pin_map = { HAL_USER_NORMAL : "user_pin", HAL_USER_SO : "so_pin", HAL_USER_WHEEL : "wheel_pin" }


def setUpModule():
    global hsm
    hsm = HSM()
    hsm.debug_io = args.io_log

def tearDownModule():
    hsm.logout()
    #hsm.close()


# Subclass a few bits of unittest to add timing reports for individual tests.

class TestCase(unittest.TestCase):

    def setUp(self):
        super(TestCase, self).setUp()
        self.startTime = datetime.datetime.now()

    def tearDown(self):
        self.endTime = datetime.datetime.now()
        super(TestCase, self).tearDown()

class TextTestResult(unittest.TextTestResult):

    def addSuccess(self, test):
        if self.showAll and hasattr(test, "startTime") and hasattr(test, "endTime"):
            self.stream.write("runtime {} ... ".format(test.endTime - test.startTime))
            self.stream.flush()
        super(TextTestResult, self).addSuccess(test)

    def addError(self, test, err):
        if self.showAll:
            self.stream.write("exception {!s} ".format(err[0].__name__)) # err[1]
            self.stream.flush()
        super(TextTestResult, self).addError(test, err)

class TextTestRunner(unittest.TextTestRunner):
    resultclass = TextTestResult


# Tests below here


class TestBasic(TestCase):
    """
    Test basic functions that don't involve keys, digests, or PINs.
    """

    def test_get_version(self):
        version = hsm.get_version()
        # Might want to inspect the result here
        self.assertIsInstance(version, int)

    def test_get_random(self):
        length = 32
        random = hsm.get_random(length)
        self.assertIsInstance(random, str)
        self.assertEqual(length, len(random))


class TestPIN(TestCase):
    """
    Test functions involving PINs.
    """

    def setUp(self):
        hsm.logout()
        super(TestPIN, self).setUp()

    def tearDown(self):
        super(TestPIN, self).tearDown()
        hsm.logout()

    def test_is_logged_in(self):
        for user in pin_map:
            self.assertRaises(HAL_ERROR_FORBIDDEN, hsm.is_logged_in, user)

    def login_logout(self, user1):
        pin = getattr(args, pin_map[user1])
        hsm.login(user1, pin)
        for user2 in pin_map:
            if user2 == user1:
                hsm.is_logged_in(user2)
            else:
                self.assertRaises(HAL_ERROR_FORBIDDEN, hsm.is_logged_in, user2)
        hsm.logout()

    def test_login_wheel(self):
        self.login_logout(HAL_USER_WHEEL)

    def test_login_so(self):
        self.login_logout(HAL_USER_SO)

    def test_login_user(self):
        self.login_logout(HAL_USER_NORMAL)

    # Eventually we will want a test of set_pin(), probably under a
    # @unittest.skipUnless to prevent it from being run unless the
    # user requests it.  Punt that one for the moment.


class TestDigest(TestCase):
    """
    Test digest/HMAC functions.
    """

    # Should use NIST test vectors, this is just a placeholder.

    def test_basic_hash(self):
        h = hsm.hash_initialize(HAL_DIGEST_ALGORITHM_SHA256)
        h.update("Hi, Mom")
        h.finalize()

    def test_basic_hmac(self):
        h = hsm.hash_initialize(HAL_DIGEST_ALGORITHM_SHA256, key = "secret")
        h.update("Hi, Dad")
        h.finalize()


# Will need something to test for pkey access when not logged in
# properly (ie, test that we get an appropriate exception under a long
# list of screwy conditions and that we don't get it under another
# long list of screwy conditions, due to the PKCS #11 compatible
# access check semantics).  Defer for now.


class TestCaseLoggedIn(TestCase):
    """
    Abstract class to handle login for PKey tests.
    """

    @classmethod
    def setUpClass(cls):
        hsm.login(HAL_USER_NORMAL, args.user_pin)

    @classmethod
    def tearDownClass(cls):
        hsm.logout()


class TestPKeyGen(TestCaseLoggedIn):
    """
    Tests involving key generation.
    """

    def sign_verify(self, hashalg, k1, k2):
        h = hsm.hash_initialize(hashalg)
        h.update("Your mother was a hamster")
        data = h.finalize()
        sig = k1.sign(data = data)
        k1.verify(signature = sig, data = data)
        k2.verify(signature = sig, data = data)

    def gen_sign_verify_rsa(self, hashalg, keylen):
        k1 = hsm.pkey_generate_rsa(keylen, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(k1.public_key, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        self.sign_verify(hashalg, k1, k2)

    def gen_sign_verify_ecdsa(self, hashalg, curve):
        k1 = hsm.pkey_generate_ec(curve, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(k1.public_key, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        self.sign_verify(hashalg, k1, k2)

    def test_gen_sign_verify_ecdsa_p256_sha256(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256)

    def test_gen_sign_verify_ecdsa_p384_sha384(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384)

    def test_gen_sign_verify_ecdsa_p521_sha512(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521)

    def test_gen_sign_verify_rsa_1024_sha256(self):
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024)

    @unittest.skipUnless(args.all_tests, "Slow")
    def test_gen_sign_verify_rsa_2048_sha384(self):
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048)

    @unittest.skipUnless(args.all_tests, "Hideously slow")
    def test_gen_sign_verify_rsa_4096_sha512(self):
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096)

    def test_gen_unsupported_length(self):
        with self.assertRaises(HAL_ERROR_BAD_ARGUMENTS):
            hsm.pkey_generate_rsa(1028).delete()

class TestPKeyHashing(TestCaseLoggedIn):
    """
    Tests involving various ways of doing the hashing for public key operations.
    """

    def load_sign_verify_rsa(self, alg, keylen, method):
        k1 = hsm.pkey_load(PreloadedKey.db[HAL_KEY_TYPE_RSA_PRIVATE, keylen].der,
                           HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(PreloadedKey.db[HAL_KEY_TYPE_RSA_PUBLIC, keylen].der,
                           HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        method(alg, k1, k2)

    def load_sign_verify_ecdsa(self, alg, curve, method):
        k1 = hsm.pkey_load(PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, curve].der,
                           HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(PreloadedKey.db[HAL_KEY_TYPE_EC_PUBLIC, curve].der,
                           HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        method(alg, k1, k2)

    @staticmethod
    def h(alg, mixed_mode = False):
        h = hsm.hash_initialize(alg, mixed_mode = mixed_mode)
        h.update("Your mother was a hamster")
        return h

    def sign_verify_data(self, alg, k1, k2):
        data = self.h(alg, mixed_mode = True).finalize()
        sig = k1.sign(data = data)
        k1.verify(signature = sig, data = data)
        k2.verify(signature = sig, data = data)

    def sign_verify_remote_remote(self, alg, k1, k2):
        sig = k1.sign(hash = self.h(alg, mixed_mode = False))
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = False))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = False))

    def sign_verify_remote_local(self, alg, k1, k2):
        sig = k1.sign(hash = self.h(alg, mixed_mode = False))
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = True))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = True))

    def sign_verify_local_remote(self, alg, k1, k2):
        sig = k1.sign(hash = self.h(alg, mixed_mode = True))
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = False))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = False))

    def sign_verify_local_local(self, alg, k1, k2):
        sig = k1.sign(hash = self.h(alg, mixed_mode = True))
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = True))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = True))

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_1024_sha256_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_data)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_2048_sha384_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_data)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_4096_sha512_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_data)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p256_sha256_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_data)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p384_sha384_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_data)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p521_sha512_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_data)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_1024_sha256_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_remote_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_2048_sha384_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_remote_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_4096_sha512_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_remote_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p256_sha256_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_remote_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p384_sha384_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_remote_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p521_sha512_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_remote_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_1024_sha256_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_remote_local)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_2048_sha384_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_remote_local)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_4096_sha512_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_remote_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p256_sha256_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_remote_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p384_sha384_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_remote_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p521_sha512_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_remote_local)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_1024_sha256_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_local_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_2048_sha384_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_local_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_4096_sha512_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_local_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p256_sha256_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_local_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p384_sha384_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_local_remote)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p521_sha512_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_local_remote)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_1024_sha256_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_local_local)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_2048_sha384_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_local_local)

    @unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
    def test_load_sign_verify_rsa_4096_sha512_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_local_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p256_sha256_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_local_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p384_sha384_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_local_local)

    @unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
    def test_load_sign_verify_ecdsa_p521_sha512_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_local_local)


@unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
class TestPKeyRSAInterop(TestCaseLoggedIn):

    @staticmethod
    def h(alg, text):
        h = hsm.hash_initialize(alg, mixed_mode = True)
        h.update(text)
        return h

    def load_sign_verify_rsa(self, alg, pyhash, keylen):
        hamster = "Your mother was a hamster"
        sk = PreloadedKey.db[HAL_KEY_TYPE_RSA_PRIVATE, keylen]
        vk = PreloadedKey.db[HAL_KEY_TYPE_RSA_PUBLIC,  keylen]
        k1 = hsm.pkey_load(sk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(vk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        sig1 = k1.sign(hash = self.h(alg, hamster))
        sig2 = sk.sign(hamster, pyhash)
        self.assertEqual(sig1, sig2)
        k1.verify(signature = sig2, hash = self.h(alg, hamster))
        k2.verify(signature = sig2, hash = self.h(alg, hamster))
        sk.verify(hamster, pyhash, sig1)
        vk.verify(hamster, pyhash, sig1)

    def test_interop_rsa_1024_sha256(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, SHA256, 1024)

    def test_interop_rsa_2048_sha384(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, SHA384, 2048)

    def test_interop_rsa_4096_sha512(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, SHA512, 4096)


@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyECDSAInterop(TestCaseLoggedIn):

    @staticmethod
    def h(alg, text):
        h = hsm.hash_initialize(alg, mixed_mode = True)
        h.update(text)
        return h

    def load_sign_verify_ecdsa(self, alg, pyhash, curve):
        hamster = "Your mother was a hamster"
        sk = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, curve]
        vk = PreloadedKey.db[HAL_KEY_TYPE_EC_PUBLIC,  curve]
        k1 = hsm.pkey_load(sk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(vk.der, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k2.delete)
        sig1 = k1.sign(hash = self.h(alg, hamster))
        sig2 = sk.sign(hamster, pyhash)
        k1.verify(signature = sig2, hash = self.h(alg, hamster))
        k2.verify(signature = sig2, hash = self.h(alg, hamster))
        vk.verify(hamster, pyhash, sig1)

    def test_interop_ecdsa_p256_sha256(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, SHA256, HAL_CURVE_P256)

    def test_interop_ecdsa_p384_sha384(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, SHA384, HAL_CURVE_P384)

    def test_interop_ecdsa_p521_sha512(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, SHA512, HAL_CURVE_P521)


class TestPKeyMatch(TestCaseLoggedIn):
    """
    Tests involving PKey list and match functions.
    """

    def load_keys(self, flags):
        uuids = set()
        for obj in PreloadedKey.db.itervalues():
            with hsm.pkey_load(obj.der, flags) as k:
                self.addCleanup(lambda uuid: hsm.pkey_open(uuid, flags = flags).delete(), k.uuid)
                uuids.add(k.uuid)
                k.set_attributes(dict((i, a) for i, a in enumerate((str(obj.keytype), str(obj.fn2)))))
        return uuids

    def match(self, flags, **kwargs):
        uuids = kwargs.pop("uuids", None)
        kwargs.update(flags = flags)
        n = 0
        for uuid in hsm.pkey_match(**kwargs):
            if uuids is None or uuid in uuids:
                with hsm.pkey_open(uuid, flags) as k:
                    n += 1
                    yield n, k

    def ks_match(self, flags):
        tags  = []
        uuids = set()
        for i in xrange(2):
            uuids |= self.load_keys(flags)
            tags.extend(PreloadedKey.db)
        self.assertEqual(len(tags), len(uuids))

        self.assertEqual(uuids, set(k.uuid for n, k in self.match(flags = flags, uuids = uuids)))

        for keytype in set(HALKeyType.index.itervalues()) - {HAL_KEY_TYPE_NONE}:
            for n, k in self.match(flags = flags, uuids = uuids, type = keytype):
                self.assertEqual(k.key_type, keytype)
                self.assertEqual(k.get_attributes({0}).pop(0), str(keytype))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t1 == keytype))

        for curve in set(HALCurve.index.itervalues()) - {HAL_CURVE_NONE}:
            for n, k in self.match(flags = flags, uuids = uuids, curve = curve):
                self.assertEqual(k.key_curve, curve)
                self.assertEqual(k.get_attributes({1}).pop(1), str(curve))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_EC_PUBLIC,
                                           HAL_KEY_TYPE_EC_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t2 == curve))

        for keylen in set(kl for kt, kl in tags if not isinstance(kl, Enum)):
            for n, k in self.match(flags = flags, uuids = uuids,
                                   attributes = {1 : str(keylen)}):
                self.assertEqual(keylen, int(k.get_attributes({1}).pop(1)))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_RSA_PUBLIC,
                                           HAL_KEY_TYPE_RSA_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags
                                    if not isinstance(t2, Enum) and  t2 == keylen))

        for n, k in self.match(flags = flags, uuids = uuids,
                               type = HAL_KEY_TYPE_RSA_PUBLIC, attributes = {1 : "2048"}):
            self.assertEqual(k.key_type, HAL_KEY_TYPE_RSA_PUBLIC)
        self.assertEqual(n, sum(1 for t1, t2 in tags
                                if t1 == HAL_KEY_TYPE_RSA_PUBLIC and t2 == 2048))

    def test_ks_match_token(self):
        self.ks_match(HAL_KEY_FLAG_TOKEN)

    def test_ks_match_volatile(self):
        self.ks_match(0)


class TestPKeyAttribute(TestCaseLoggedIn):
    """
    Attribute creation/lookup/deletion tests.
    """

    def load_and_fill(self, flags, n_keys = 1, n_attrs = 2, n_fill = 0):
        pinwheel = Pinwheel()
        for i in xrange(n_keys):
            for obj in PreloadedKey.db.itervalues():
                with hsm.pkey_load(obj.der, flags) as k:
                    pinwheel()
                    self.addCleanup(lambda uuid: hsm.pkey_open(uuid, flags = flags).delete(), k.uuid)
                    k.set_attributes(dict((j, "Attribute {}{}".format(j, "*" * n_fill))
                                          for j in xrange(n_attrs)))
                    pinwheel()

    def test_attribute_bloat_volatile_many(self):
        self.load_and_fill(0, n_attrs = 128) # 192

    def test_attribute_bloat_volatile_big(self):
        self.load_and_fill(0, n_attrs = 6, n_fill = 512)

    def test_attribute_bloat_token_many(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 128)

    def test_attribute_bloat_token_big(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 4, n_fill = 512) # [16, 1024]


@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyAttributeP11(TestCaseLoggedIn):
    """
    Attribute creation/lookup/deletion tests based on a PKCS #11 trace.
    """

    def setUp(self):
        der = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256].der
        self.k = hsm.pkey_load(der, HAL_KEY_FLAG_TOKEN)
        self.addCleanup(self.k.delete)
        super(TestPKeyAttributeP11, self).setUp()

    def test_set_many_attributes(self):
        self.k.set_attributes({
            0x001 : "\x01",
            0x108 : "\x01",
            0x105 : "\x00",
            0x002 : "\x01",
            0x107 : "\x00",
            0x102 : "\x45\x43\x2d\x50\x32\x35\x36",
            0x003 : "\x45\x43\x2d\x50\x32\x35\x36",
            0x162 : "\x00",
            0x103 : "\x01",
            0x000 : "\x03\x00\x00\x00",
            0x100 : "\x03\x00\x00\x00",
            0x101 : "",
            0x109 : "\x00",
            0x10c : "\x00",
            0x110 : "",
            0x111 : "",
            0x163 : "\x00",
            0x166 : "\xff\xff\xff\xff",
            0x170 : "\x01",
            0x210 : "\x00",
            0x163 : "\x01",
            0x166 : "\x40\x10\x00\x00",
            0x180 : "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" })

    def test_set_many_attributes_with_deletions(self):
        self.k.set_attributes({
            0x001 : "\x01",
            0x108 : "\x01",
            0x105 : "\x00",
            0x002 : "\x01",
            0x107 : "\x00",
            0x102 : "\x45\x43\x2d\x50\x32\x35\x36",
            0x003 : "\x45\x43\x2d\x50\x32\x35\x36",
            0x162 : "\x00",
            0x103 : "\x01",
            0x000 : "\x03\x00\x00\x00",
            0x100 : "\x03\x00\x00\x00",
            0x101 : None,
            0x109 : "\x00",
            0x10c : "\x00",
            0x110 : None,
            0x111 : None,
            0x163 : "\x00",
            0x166 : "\xff\xff\xff\xff",
            0x170 : "\x01",
            0x210 : "\x00",
            0x163 : "\x01",
            0x166 : "\x40\x10\x00\x00",
            0x180 : "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" })


@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyAttributeWriteSpeedToken(TestCaseLoggedIn):
    """
    Attribute speed tests.
    """

    def setUp(self):
        der = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256].der
        self.k = hsm.pkey_load(der, HAL_KEY_FLAG_TOKEN)
        self.addCleanup(self.k.delete)
        super(TestPKeyAttributeWriteSpeedToken, self).setUp()

    def set_attributes(self, n_attrs):
        self.k.set_attributes(dict((i, "Attribute {}".format(i))
                                   for i in xrange(n_attrs)))

    def test_set_1_attribute(self):
        self.set_attributes(1)

    def test_set_6_attributes(self):
        self.set_attributes(6)

    def test_set_12_attributes(self):
        self.set_attributes(12)

@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyAttributeWriteSpeedVolatile(TestCaseLoggedIn):
    """
    Attribute speed tests.
    """

    def setUp(self):
        der = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256].der
        self.k = hsm.pkey_load(der, 0)
        self.addCleanup(self.k.delete)
        super(TestPKeyAttributeWriteSpeedVolatile, self).setUp()

    def set_attributes(self, n_attrs):
        self.k.set_attributes(dict((i, "Attribute {}".format(i))
                                   for i in xrange(n_attrs)))

    def test_set_1_attribute(self):
        self.set_attributes(1)

    def test_set_6_attributes(self):
        self.set_attributes(6)

    def test_set_12_attributes(self):
        self.set_attributes(12)

@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyAttributeReadSpeedToken(TestCaseLoggedIn):
    """
    Attribute speed tests.
    """

    def setUp(self):
        der = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256].der
        self.k = hsm.pkey_load(der, HAL_KEY_FLAG_TOKEN)
        self.addCleanup(self.k.delete)
        self.k.set_attributes(dict((i, "Attribute {}".format(i))
                                   for i in xrange(12)))
        super(TestPKeyAttributeReadSpeedToken, self).setUp()

    def verify_attributes(self, n_attrs, attributes):
        expected = dict((i, "Attribute {}".format(i))
                        for i in xrange(n_attrs))
        self.assertEqual(attributes, expected)

    def get_attributes(self, n_attrs):
        attributes = self.k.get_attributes(range(n_attrs))
        self.verify_attributes(n_attrs, attributes)

    def test_get_1_attribute(self):
        self.get_attributes(1)

    def test_get_6_attributes(self):
        self.get_attributes(6)

    def test_get_12_attributes(self):
        self.get_attributes(12)

@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPKeyAttributeReadSpeedVolatile(TestCaseLoggedIn):
    """
    Attribute speed tests.
    """

    def setUp(self):
        der = PreloadedKey.db[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256].der
        self.k = hsm.pkey_load(der, 0)
        self.addCleanup(self.k.delete)
        self.k.set_attributes(dict((i, "Attribute {}".format(i))
                                   for i in xrange(12)))
        super(TestPKeyAttributeReadSpeedVolatile, self).setUp()

    def verify_attributes(self, n_attrs, attributes):
        expected = dict((i, "Attribute {}".format(i))
                        for i in xrange(n_attrs))
        self.assertEqual(attributes, expected)

    def get_attributes(self, n_attrs):
        attributes = self.k.get_attributes(range(n_attrs))
        self.verify_attributes(n_attrs, attributes)

    def test_get_1_attribute(self):
        self.get_attributes(1)

    def test_get_6_attributes(self):
        self.get_attributes(6)

    def test_get_12_attributes(self):
        self.get_attributes(12)


@unittest.skipUnless(ecdsa_loaded, "Requires Python ECDSA package")
class TestPkeyECDSAVerificationNIST(TestCaseLoggedIn):
    """
    ECDSA verification tests based on Suite B Implementer's Guide to FIPS 186-3.
    """

    def verify(self, Qx, Qy, H, r, s, py_curve, py_hash):
        Q = ECDSA_VerifyingKey.from_public_point(Point(py_curve.curve, Qx, Qy),
                                                 py_curve, py_hash).to_der()
        k  = hsm.pkey_load(Q, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k.delete)
        k.verify(signature = (r + s).decode("hex"), data = H.decode("hex"))

    def test_suite_b_p256_verify(self):
        self.verify(
            Qx = 0x8101ece47464a6ead70cf69a6e2bd3d88691a3262d22cba4f7635eaff26680a8,
            Qy = 0xd8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a5abaa624079936c0c3a9,
            H  = "7c3e883ddc8bd688f96eac5e9324222c8f30f9d6bb59e9c5f020bd39ba2b8377",
            r  = "7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c",
            s  = "7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367",
            py_curve  = NIST256p,
            py_hash   = SHA256)

    def test_suite_b__p384_verify(self):
        self.verify(
            Qx = 0x1fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0,
            Qy = 0xeb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9,
            H  = "b9210c9d7e20897ab86597266a9d5077e8db1b06f7220ed6ee75bd8b45db37891f8ba5550304004159f4453dc5b3f5a1",
            r  = "a0c27ec893092dea1e1bd2ccfed3cf945c8134ed0c9f81311a0f4a05942db8dbed8dd59f267471d5462aa14fe72de856",
            s  = "20ab3f45b74f10b6e11f96a2c8eb694d206b9dda86d3c7e331c26b22c987b7537726577667adadf168ebbe803794a402",
            py_curve  = NIST384p,
            py_hash   = SHA384)


@unittest.skipUnless(pycrypto_loaded, "Requires Python Crypto package")
class TestPKeyBackup(TestCaseLoggedIn):

    oid_rsaEncryption = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
    oid_aesKeyWrap    = "\x60\x86\x48\x01\x65\x03\x04\x01\x30"

    @staticmethod
    def parse_EncryptedPrivateKeyInfo(der, oid):
        from Crypto.Util.asn1 import DerObject, DerSequence, DerOctetString, DerObjectId
        encryptedPrivateKeyInfo = DerSequence()
        encryptedPrivateKeyInfo.decode(der)
        encryptionAlgorithm = DerSequence()
        encryptionAlgorithm.decode(encryptedPrivateKeyInfo[0])
        algorithm = DerObjectId()
        algorithm.decode(encryptionAlgorithm[0])
        encryptedData = DerOctetString()
        encryptedData.decode(encryptedPrivateKeyInfo[1])
        if algorithm.payload != oid:
            raise ValueError
        return encryptedData.payload

    @staticmethod
    def encode_EncryptedPrivateKeyInfo(der, oid):
        from Crypto.Util.asn1 import DerSequence, DerOctetString
        return DerSequence([
            DerSequence([chr(0x06) + chr(len(oid)) + oid]).encode(),
            DerOctetString(der).encode()
        ]).encode()

    @staticmethod
    def make_kek():
        import Crypto.Random
        return Crypto.Random.new().read(256/8)

    def sig_check(self, pkey, der):
        from Crypto.Util.asn1 import DerSequence, DerNull, DerOctetString
        p115 = PKCS115_SigScheme(RSA.importKey(der))
        hash = SHA256("Your mother was a hamster")
        data = DerSequence([
            DerSequence([hash.oid, DerNull().encode()]).encode(),
            DerOctetString(hash.digest()).encode()
        ]).encode()
        sig1 = p115.sign(hash)
        sig2 = pkey.sign(data = data)
        self.assertEqual(sig1, sig2)
        p115.verify(hash, sig1)
        p115.verify(hash, sig2)
        pkey.verify(signature = sig1, data = data)
        pkey.verify(signature = sig2, data = data)

    def test_export(self):
        kekek = hsm.pkey_load(
            flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT,
            der   = PreloadedKey.db[HAL_KEY_TYPE_RSA_PUBLIC, 1024].der)
        self.addCleanup(kekek.delete)
        pkey = hsm.pkey_generate_rsa(
            keylen= 1024,
            flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_EXPORTABLE)
        self.addCleanup(pkey.delete)
        pkcs8_der, kek_der = kekek.export_pkey(pkey)
        kek = PKCS115_Cipher(PreloadedKey.db[HAL_KEY_TYPE_RSA_PRIVATE, 1024].obj).decrypt(
            self.parse_EncryptedPrivateKeyInfo(kek_der, self.oid_rsaEncryption),
            self.make_kek())
        der = AESKeyWrapWithPadding(kek).unwrap(
            self.parse_EncryptedPrivateKeyInfo(pkcs8_der, self.oid_aesKeyWrap))
        self.sig_check(pkey, der)

    def test_import(self):
        kekek = hsm.pkey_generate_rsa(
            keylen= 1024,
            flags = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT)
        self.addCleanup(kekek.delete)
        kek = self.make_kek()
        der = PreloadedKey.db[HAL_KEY_TYPE_RSA_PRIVATE, 1024].der
        pkey = kekek.import_pkey(
            pkcs8 = self.encode_EncryptedPrivateKeyInfo(
                AESKeyWrapWithPadding(kek).wrap(der),
                self.oid_aesKeyWrap),
            kek = self.encode_EncryptedPrivateKeyInfo(
                PKCS115_Cipher(RSA.importKey(kekek.public_key)).encrypt(kek),
                self.oid_rsaEncryption),
            flags = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(pkey.delete)
        self.sig_check(pkey, der)


class AESKeyWrapWithPadding(object):
    """
    Implementation of AES Key Wrap With Padding from RFC 5649.
    """

    class UnwrapError(Exception):
        "Something went wrong during unwrap."

    def __init__(self, key):
        self.ctx = AES.new(key, AES.MODE_ECB)

    def _encrypt(self, b1, b2):
        aes_block = self.ctx.encrypt(b1 + b2)
        return aes_block[:8], aes_block[8:]

    def _decrypt(self, b1, b2):
        aes_block = self.ctx.decrypt(b1 + b2)
        return aes_block[:8], aes_block[8:]

    @staticmethod
    def _start_stop(start, stop):               # Syntactic sugar
        step = -1 if start > stop else 1
        return xrange(start, stop + step, step)

    def wrap(self, Q):
        "RFC 5649 section 4.1."
        m = len(Q)                              # Plaintext length
        if m % 8 != 0:                          # Pad Q if needed
            Q += "\x00" * (8 - (m % 8))
        R = [pack(">LL", 0xa65959a6, m)]        # Magic MSB(32,A), build LSB(32,A)
        R.extend(Q[i : i + 8]                   # Append Q
                 for i in xrange(0, len(Q), 8))
        n = len(R) - 1
        if n == 1:
            R[0], R[1] = self._encrypt(R[0], R[1])
        else:
            # RFC 3394 section 2.2.1
            for j in self._start_stop(0, 5):
                for i in self._start_stop(1, n):
                    R[0], R[i] = self._encrypt(R[0], R[i])
                    W0, W1 = unpack(">LL", R[0])
                    W1 ^= n * j + i
                    R[0] = pack(">LL", W0, W1)
        assert len(R) == (n + 1) and all(len(r) == 8 for r in R)
        return "".join(R)

    def unwrap(self, C):
        "RFC 5649 section 4.2."
        if len(C) % 8 != 0:
            raise self.UnwrapError("Ciphertext length {} is not an integral number of blocks"
                                   .format(len(C)))
        n = (len(C) / 8) - 1
        R = [C[i : i + 8] for i in xrange(0, len(C), 8)]
        if n == 1:
            R[0], R[1] = self._decrypt(R[0], R[1])
        else:
            # RFC 3394 section 2.2.2 steps (1), (2), and part of (3)
            for j in self._start_stop(5, 0):
                for i in self._start_stop(n, 1):
                    W0, W1 = unpack(">LL", R[0])
                    W1 ^= n * j + i
                    R[0] = pack(">LL", W0, W1)
                    R[0], R[i] = self._decrypt(R[0], R[i])
        magic, m = unpack(">LL", R[0])
        if magic != 0xa65959a6:
            raise self.UnwrapError("Magic value in AIV should have been 0xa65959a6, was 0x{:02x}"
                              .format(magic))
        if m <= 8 * (n - 1) or m > 8 * n:
            raise self.UnwrapError("Length encoded in AIV out of range: m {}, n {}".format(m, n))
        R = "".join(R[1:])
        assert len(R) ==  8 * n
        if any(r != "\x00" for r in R[m:]):
            raise self.UnwrapError("Nonzero trailing bytes {}".format(R[m:].encode("hex")))
        return R[:m]


class Pinwheel(object):
    """
    Activity pinwheel, as needed.
    """

    def __init__(self):
        self.pinwheel = tuple("\b\b{} ".format(c) for c in "-/|\\")
        self.modulo   = len(self.pinwheel)
        self.position = 0
        if not args.quiet:
            from sys import stdout
            stdout.write(". ")
            stdout.flush()

    def __call__(self):
        if not args.quiet:
            from sys import stdout
            stdout.write(self.pinwheel[self.position])
            stdout.flush()
            self.position = (self.position + 1) % self.modulo


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
        if pycrypto_loaded:
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
        if ecdsa_loaded:
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
    main()
