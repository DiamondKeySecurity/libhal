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
import sys

from libhal import *

try:
    from Crypto.Util.number     import inverse
    from Crypto.PublicKey       import RSA
    from Crypto.Signature       import PKCS1_v1_5
    from Crypto.Hash.SHA256     import SHA256Hash as SHA256
    from Crypto.Hash.SHA384     import SHA384Hash as SHA384
    from Crypto.Hash.SHA512     import SHA512Hash as SHA512
    pycrypto_loaded = True
except ImportError:
    pycrypto_loaded = False


try:
    from ecdsa.keys             import SigningKey as ECDSA_SigningKey, VerifyingKey as ECDSA_VerifyingKey
    from ecdsa.ellipticcurve    import Point
    from ecdsa.curves           import NIST256p, NIST384p, NIST521p
    if not pycrypto_loaded:
        from hashlib            import sha256 as SHA256, sha384 as SHA384, sha512 as SHA512
    ecdsa_loaded = True
except ImportError:
    ecdsa_loaded = False


def log(msg):
    if not args.quiet:
        sys.stderr.write(msg)
        sys.stderr.write("\n")


def main():
    preload_public_keys()
    from sys import argv
    global args
    args = parse_arguments(argv[1:])
    argv = argv[:1] + args.only_test
    unittest.main(verbosity = 1 if args.quiet else 2, argv = argv, catchbreak = True, testRunner = TextTestRunner)

def parse_arguments(argv = ()):
    from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
    parser = ArgumentParser(description = __doc__, formatter_class = ArgumentDefaultsHelpFormatter)
    parser.add_argument("--quiet",      action = "store_true",          help = "suppress chatter")
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

class TextTestRunner(unittest.TextTestRunner):
    resultclass = TextTestResult


# Tests below here


class TestBasic(TestCase):
    """
    Test basic functions that don't involve keys, digests, or PINs.
    """

    def test_get_version(self):
        "Test whether get_version() works"
        version = hsm.get_version()
        # Might want to inspect the result here
        self.assertIsInstance(version, int)

    def test_get_random(self):
        "Test whether get_random() works"
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
        "Test whether is_logged_in() returns correct exception when not logged in"
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
        k1 = hsm.pkey_generate_rsa(keylen)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_RSA_PUBLIC, HAL_CURVE_NONE, k1.public_key)
        self.addCleanup(k2.delete)
        self.sign_verify(hashalg, k1, k2)

    def gen_sign_verify_ecdsa(self, hashalg, curve):
        k1 = hsm.pkey_generate_ec(curve)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_EC_PUBLIC, curve, k1.public_key)
        self.addCleanup(k2.delete)
        self.sign_verify(hashalg, k1, k2)

    def test_gen_sign_verify_ecdsa_p256_sha256(self):
        "Generate/sign/verify with ECDSA-P256-SHA-256"
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256)

    def test_gen_sign_verify_ecdsa_p384_sha384(self):
        "Generate/sign/verify with ECDSA-P384-SHA-384"
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384)

    def test_gen_sign_verify_ecdsa_p521_sha512(self):
        "Generate/sign/verify with ECDSA-P521-SHA-512"
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521)

    def test_gen_sign_verify_rsa_1024_p256_sha256(self):
        "Generate/sign/verify with RSA-1024-SHA-256"
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024)

    @unittest.skipUnless(args.all_tests, "Slow")
    def test_gen_sign_verify_rsa_2048_sha384(self):
        "Generate/sign/verify with RSA-2048-SHA-384"
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048)

    @unittest.skipUnless(args.all_tests, "Hideously slow")
    def test_gen_sign_verify_rsa_4096_sha512(self):
        "Generate/sign/verify with RSA-4096-SHA-512"
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096)

    def test_gen_unsupported_length(self):
        "Key length not multiple of 32 bits"
        with self.assertRaises(HAL_ERROR_BAD_ARGUMENTS):
            hsm.pkey_generate_rsa(1028).delete()

class TestPKeyHashing(TestCaseLoggedIn):
    """
    Tests involving various ways of doing the hashing for public key operations.
    """

    def load_sign_verify_rsa(self, alg, keylen, method):
        k1 = hsm.pkey_load(HAL_KEY_TYPE_RSA_PRIVATE, HAL_CURVE_NONE,
                           static_keys[HAL_KEY_TYPE_RSA_PRIVATE, keylen].exportKey("DER"))
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_RSA_PUBLIC, HAL_CURVE_NONE,
                           static_keys[HAL_KEY_TYPE_RSA_PUBLIC, keylen].exportKey("DER"))
        self.addCleanup(k2.delete)
        method(alg, k1, k2)

    def load_sign_verify_ecdsa(self, alg, curve, method):
        k1 = hsm.pkey_load(HAL_KEY_TYPE_EC_PRIVATE, curve,
                           static_keys[HAL_KEY_TYPE_EC_PRIVATE, curve].to_der())
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_EC_PUBLIC, curve,
                           static_keys[HAL_KEY_TYPE_EC_PUBLIC, curve].to_der())
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

    def test_load_sign_verify_rsa_1024_sha256_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_data)

    def test_load_sign_verify_rsa_2048_sha384_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_data)

    def test_load_sign_verify_rsa_4096_sha512_data(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_data)

    def test_load_sign_verify_ecdsa_p256_sha256_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_data)

    def test_load_sign_verify_ecdsa_p384_sha384_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_data)

    def test_load_sign_verify_ecdsa_p521_sha512_data(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_data)

    def test_load_sign_verify_rsa_1024_sha256_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_remote_remote)

    def test_load_sign_verify_rsa_2048_sha384_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_remote_remote)

    def test_load_sign_verify_rsa_4096_sha512_remote_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_remote_remote)

    def test_load_sign_verify_ecdsa_p256_sha256_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_remote_remote)

    def test_load_sign_verify_ecdsa_p384_sha384_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_remote_remote)

    def test_load_sign_verify_ecdsa_p521_sha512_remote_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_remote_remote)

    def test_load_sign_verify_rsa_1024_sha256_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_remote_local)

    def test_load_sign_verify_rsa_2048_sha384_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_remote_local)

    def test_load_sign_verify_rsa_4096_sha512_remote_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_remote_local)

    def test_load_sign_verify_ecdsa_p256_sha256_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_remote_local)

    def test_load_sign_verify_ecdsa_p384_sha384_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_remote_local)

    def test_load_sign_verify_ecdsa_p521_sha512_remote_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_remote_local)

    def test_load_sign_verify_rsa_1024_sha256_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_local_remote)

    def test_load_sign_verify_rsa_2048_sha384_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_local_remote)

    def test_load_sign_verify_rsa_4096_sha512_local_remote(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_local_remote)

    def test_load_sign_verify_ecdsa_p256_sha256_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_local_remote)

    def test_load_sign_verify_ecdsa_p384_sha384_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_local_remote)

    def test_load_sign_verify_ecdsa_p521_sha512_local_remote(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_local_remote)

    def test_load_sign_verify_rsa_1024_sha256_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024, self.sign_verify_local_local)

    def test_load_sign_verify_rsa_2048_sha384_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048, self.sign_verify_local_local)

    def test_load_sign_verify_rsa_4096_sha512_local_local(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096, self.sign_verify_local_local)

    def test_load_sign_verify_ecdsa_p256_sha256_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256, self.sign_verify_local_local)

    def test_load_sign_verify_ecdsa_p384_sha384_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384, self.sign_verify_local_local)

    def test_load_sign_verify_ecdsa_p521_sha512_local_local(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521, self.sign_verify_local_local)


class TestPKeyRSAInterop(TestCaseLoggedIn):

    @staticmethod
    def h(alg, text):
        h = hsm.hash_initialize(alg, mixed_mode = True)
        h.update(text)
        return h

    def load_sign_verify_rsa(self, alg, pyhash, keylen):
        hamster = "Your mother was a hamster"
        sk = static_keys[HAL_KEY_TYPE_RSA_PRIVATE, keylen]
        vk = static_keys[HAL_KEY_TYPE_RSA_PUBLIC,  keylen]
        k1 = hsm.pkey_load(HAL_KEY_TYPE_RSA_PRIVATE, HAL_CURVE_NONE, sk.exportKey("DER"))
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_RSA_PUBLIC,  HAL_CURVE_NONE, vk.exportKey("DER"))
        self.addCleanup(k2.delete)
        sk = PKCS1_v1_5.PKCS115_SigScheme(sk)
        vk = PKCS1_v1_5.PKCS115_SigScheme(vk)
        sig1 = k1.sign(hash = self.h(alg, hamster))
        sig2 = sk.sign(pyhash(hamster))
        self.assertEqual(sig1, sig2)
        k1.verify(signature = sig2, hash = self.h(alg, hamster))
        k2.verify(signature = sig2, hash = self.h(alg, hamster))
        sk.verify(pyhash(hamster), sig1)
        vk.verify(pyhash(hamster), sig1)

    def test_interop_rsa_1024_sha256(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, SHA256, 1024)

    def test_interop_rsa_2048_sha384(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, SHA384, 2048)

    def test_interop_rsa_4096_sha512(self):
        self.load_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, SHA512, 4096)


class TestPKeyECDSAInterop(TestCaseLoggedIn):

    @staticmethod
    def h(alg, text):
        h = hsm.hash_initialize(alg, mixed_mode = True)
        h.update(text)
        return h

    def load_sign_verify_ecdsa(self, alg, curve):
        hamster = "Your mother was a hamster"
        sk = static_keys[HAL_KEY_TYPE_EC_PRIVATE, curve]
        vk = static_keys[HAL_KEY_TYPE_EC_PUBLIC,  curve]
        k1 = hsm.pkey_load(HAL_KEY_TYPE_EC_PRIVATE, curve, sk.to_der())
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(HAL_KEY_TYPE_EC_PUBLIC,  curve, vk.to_der())
        self.addCleanup(k2.delete)
        sig1 = k1.sign(hash = self.h(alg, hamster))
        sig2 = sk.sign(hamster)
        k1.verify(signature = sig2, hash = self.h(alg, hamster))
        k2.verify(signature = sig2, hash = self.h(alg, hamster))
        vk.verify(sig1, hamster)

    def test_interop_ecdsa_p256_sha256(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256)

    def test_interop_ecdsa_p384_sha384(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384)

    def test_interop_ecdsa_p521_sha512(self):
        self.load_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521)


class TestPKeyList(TestCaseLoggedIn):
    """
    Tests involving PKey list and match functions.
    """

    def load_keys(self, flags):
        for keytype, curve in static_keys:
            obj = static_keys[keytype, curve]
            atr = (str(keytype), str(curve))
            if keytype in (HAL_KEY_TYPE_RSA_PRIVATE, HAL_KEY_TYPE_RSA_PUBLIC):
                curve = HAL_CURVE_NONE
                der   = obj.exportKey("DER")
            elif keytype in (HAL_KEY_TYPE_EC_PRIVATE, HAL_KEY_TYPE_EC_PUBLIC):
                der   = obj.to_der()
            else:
                raise ValueError
            k = hsm.pkey_load(keytype, curve, der, flags)
            self.addCleanup(lambda uuid: hsm.pkey_find(uuid, flags = flags).delete(),
                            k.uuid)
            for i, a in enumerate(atr):
                k.set_attribute(i, a)
            k.close()

    def ks_list(self, flags):
        self.load_keys(flags)
        hsm.pkey_list(flags = flags)
        hsm.pkey_match(flags = flags)

    def test_ks_list_volatile(self):
        self.ks_list(0)

    def test_ks_list_token(self):
        self.ks_list(HAL_KEY_FLAG_TOKEN)

    def match(self, flags, **kwargs):
        kwargs.update(flags = flags)
        for n, uuid in enumerate(hsm.pkey_match(**kwargs), 1):
            with hsm.pkey_find(uuid, flags) as k:
                yield n, k

    def ks_match(self, flags):
        tags = []
        for i in xrange(2):
            self.load_keys(flags)
            tags.extend(static_keys)

        uuids = set()
        for n, k in self.match(flags = flags):
            uuids.add(k.uuid)
        self.assertEqual(n, len(uuids))
        self.assertEqual(n, len(tags))

        for keytype in set(HALKeyType.index.itervalues()) - {HAL_KEY_TYPE_NONE}:
            for n, k in self.match(flags = flags, type = keytype):
                self.assertEqual(k.key_type, keytype)
                self.assertEqual(k.get_attribute(0), str(keytype))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t1 == keytype))

        for curve in set(HALCurve.index.itervalues()) - {HAL_CURVE_NONE}:
            for n, k in self.match(flags = flags, curve = curve):
                self.assertEqual(k.key_curve, curve)
                self.assertEqual(k.get_attribute(1), str(curve))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_EC_PUBLIC,
                                           HAL_KEY_TYPE_EC_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t2 == curve))

        for keylen in set(kl for kt, kl in tags if not isinstance(kl, Enum)):
            for n, k in self.match(flags = flags, attributes = {1 : str(keylen)}):
                self.assertEqual(keylen, int(k.get_attribute(1)))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_RSA_PUBLIC,
                                           HAL_KEY_TYPE_RSA_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags if not isinstance(t2, Enum) and  t2 == keylen))

        for n, k in self.match(flags = flags, type = HAL_KEY_TYPE_RSA_PUBLIC, attributes = {1 : "2048"}):
            self.assertEqual(k.key_type, HAL_KEY_TYPE_RSA_PUBLIC)
        self.assertEqual(n, sum(1 for t1, t2 in tags if t1 == HAL_KEY_TYPE_RSA_PUBLIC and t2 == 2048))

    def test_ks_match_token(self):
        self.ks_match(HAL_KEY_FLAG_TOKEN)

    def test_ks_match_volatile(self):
        self.ks_match(0)

class TestPkeyECDSAVerificationNIST(TestCaseLoggedIn):
    """
    ECDSA verification tests based on Suite B Implementer's Guide to FIPS 186-3.
    """

    def verify(self, Qx, Qy, H, r, s, hal_curve, py_curve, py_hash):
        Q = ECDSA_VerifyingKey.from_public_point(Point(py_curve.curve, Qx, Qy),
                                                 py_curve, py_hash).to_der()
        k  = hsm.pkey_load(HAL_KEY_TYPE_EC_PUBLIC, hal_curve, Q)
        self.addCleanup(k.delete)
        k.verify(signature = (r + s).decode("hex"), data = H.decode("hex"))

    def test_suite_b_p256_verify(self):
        self.verify(
            Qx = 0x8101ece47464a6ead70cf69a6e2bd3d88691a3262d22cba4f7635eaff26680a8,
            Qy = 0xd8a12ba61d599235f67d9cb4d58f1783d3ca43e78f0a5abaa624079936c0c3a9,
            H  = "7c3e883ddc8bd688f96eac5e9324222c8f30f9d6bb59e9c5f020bd39ba2b8377",
            r  = "7214bc9647160bbd39ff2f80533f5dc6ddd70ddf86bb815661e805d5d4e6f27c",
            s  = "7d1ff961980f961bdaa3233b6209f4013317d3e3f9e1493592dbeaa1af2bc367",
            hal_curve = HAL_CURVE_P256,
            py_curve  = NIST256p,
            py_hash   = SHA256)

    def test_suite_b__p384_verify(self):
        self.verify(
            Qx = 0x1fbac8eebd0cbf35640b39efe0808dd774debff20a2a329e91713baf7d7f3c3e81546d883730bee7e48678f857b02ca0,
            Qy = 0xeb213103bd68ce343365a8a4c3d4555fa385f5330203bdd76ffad1f3affb95751c132007e1b240353cb0a4cf1693bdf9,
            H  = "b9210c9d7e20897ab86597266a9d5077e8db1b06f7220ed6ee75bd8b45db37891f8ba5550304004159f4453dc5b3f5a1",
            r  = "a0c27ec893092dea1e1bd2ccfed3cf945c8134ed0c9f81311a0f4a05942db8dbed8dd59f267471d5462aa14fe72de856",
            s  = "20ab3f45b74f10b6e11f96a2c8eb694d206b9dda86d3c7e331c26b22c987b7537726577667adadf168ebbe803794a402",
            hal_curve = HAL_CURVE_P384,
            py_curve  = NIST384p,
            py_hash   = SHA384)


# Entire classes of tests still missing:
#
# * pkey attribute functions
#
# * pkey list and match functions
#
# * token vs session key tests
#
# Preloaded keys should suffice for all of these.

if False:
  class TestPKeyListMatch(TestCaseLoggedIn):

    def test_pkey_list(self):
        for flags in (0, HAL_KEY_FLAG_TOKEN):
            hsm.pkey_list(flags = flags)

    def test_pkey_match(self):
        for f in (HAL_KEY_FLAG_TOKEN, 0):
            hsm.pkey_match(flags = f)

if False:
  class TestPKeyAttribute(TestCaseLoggedIn):
    pass


# Keys for preload tests, here at the end because they're large.  For
# the moment, we use PKCS #1.5 format for RSA and secg format for
# ECDSA, because those are the formats that everything (including our
# own ASN.1 code) supports.  Arguably, we should be using PKCS #8 to
# get a single, consistent, self-identifying private key format, but
# we're not there yet and it's not particularly urgent given
# widespread availablity of conversion tools (eg, "openssl pkcs8").

static_keys = {}

# openssl genrsa 1024
if pycrypto_loaded: static_keys[HAL_KEY_TYPE_RSA_PRIVATE, 1024] = RSA.importKey('''\
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
''')

# openssl genrsa 2048
if pycrypto_loaded: static_keys[HAL_KEY_TYPE_RSA_PRIVATE, 2048] = RSA.importKey('''\
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
''')

# openssl genrsa 4096
if pycrypto_loaded: static_keys[HAL_KEY_TYPE_RSA_PRIVATE, 4096] = RSA.importKey('''\
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
''')

# openssl ecparam -genkey -name prime256v1 | openssl ec
if ecdsa_loaded: static_keys[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P256] = ECDSA_SigningKey.from_pem('''\
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPBrVhD1iFF2e8wPkPf4N1038iR8xPgku/CVOT8lcSztoAoGCCqGSM49
AwEHoUQDQgAE3mB5BmN5Fa4fV74LsDWIpBUxktPqYGJ6WOBrjPs1HWkNU7JHO3qY
9yy+CXFSPb89GWQgb5wLtNPn4QYMj+KRTA==
-----END EC PRIVATE KEY-----
''', SHA256)

# openssl ecparam -genkey -name secp384r1 | openssl ec
if ecdsa_loaded: static_keys[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P384] = ECDSA_SigningKey.from_pem('''\
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCVGo35Hbrf3Iys7mWRIm5yjg+6vPIgzbp2jCbDyszBo+wTxmQambG4
g8yocp4wM6+gBwYFK4EEACKhZANiAATYwa+M8T8jsNHKmMZTvPPflUIfrjuZZo1D
3kkkmN4r6cTNctjaeRdAfD0X40l4yPnGIP9ParuKVVl1y0TdQ7BS3g/Gj/LP33HD
ESP8gFDIKFCWSDX0uhmy+HsGsPwgNoY=
-----END EC PRIVATE KEY-----
''', SHA384)

# openssl ecparam -genkey -name secp521r1 | openssl ec
if ecdsa_loaded: static_keys[HAL_KEY_TYPE_EC_PRIVATE, HAL_CURVE_P521] = ECDSA_SigningKey.from_pem('''\
-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBtf+LKhJNQEJRFQ2cGQPcviwfp9IKSnD5EFTqAPtv7/+t2FtmdHHP
/fWIlZ7jcC5N9dWy6bKGu3+FqwgZAYLpsqigBwYFK4EEACOhgYkDgYYABADdfcUe
P0oAZQ5308v5ijcg4hePvhvVi+QKcrwmE9kirXCFoYN1tzPmXZmw8lNJenrbwaNz
opJR84LBHnomGPogAQGF0aRk0jE8w1j1oMfrrzV6vCWnkh7pyzsDnrLU1HrkWeqw
ihzwMzYJgFzToDH+fCh7nrBFZZZ9P9gPYMlSM5UMeA==
-----END EC PRIVATE KEY-----
''', SHA512)

# Public key objects corresponding to the private key objects above.

def preload_public_keys():
    for keytag, k in static_keys.items():
        keytype, len_or_curve = keytag
        if keytype == HAL_KEY_TYPE_RSA_PRIVATE:
            static_keys[HAL_KEY_TYPE_RSA_PUBLIC, len_or_curve] = k.publickey()
        elif keytype == HAL_KEY_TYPE_EC_PRIVATE:
            static_keys[HAL_KEY_TYPE_EC_PUBLIC, len_or_curve] = k.get_verifying_key()
        else:
            raise TypeError


if __name__ == "__main__":
    main()
