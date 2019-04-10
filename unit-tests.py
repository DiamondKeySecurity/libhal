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

from cryptech.libhal import *

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

    def skipUnlessAll(self, reason):
        if not args.all_tests:
            self.skipTest(reason)

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

    def v(*bytes):
        return "".join(chr(b) for b in bytes)

    # NIST sample messages.

    # "abc"
    nist_512_single = v(
        0x61, 0x62, 0x63
    )

    nist_sha1_single_digest = v(
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71,
        0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
    )

    nist_sha256_single_digest = v(
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    )

    # "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    nist_512_double = v(
        0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64, 0x65, 0x66,
        0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
        0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b, 0x69, 0x6a, 0x6b, 0x6c,
        0x6a, 0x6b, 0x6c, 0x6d, 0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
        0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71
    )

    nist_sha1_double_digest = v(
        0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae, 0x4a, 0xa1,
        0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
    )

    nist_sha256_double_digest = v(
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93,
        0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
        0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1
    )

    # "abc"
    nist_1024_single = v(
        0x61, 0x62, 0x63
    )

    nist_sha512_224_single_digest = v(
        0x46, 0x34, 0x27, 0x0f, 0x70, 0x7b, 0x6a, 0x54, 0xda, 0xae, 0x75, 0x30,
        0x46, 0x08, 0x42, 0xe2, 0x0e, 0x37, 0xed, 0x26, 0x5c, 0xee, 0xe9, 0xa4,
        0x3e, 0x89, 0x24, 0xaa
    )

    nist_sha512_256_single_digest = v(
        0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29, 0xb7,
        0x6b, 0x4c, 0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc, 0x6d, 0x46,
        0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23
    )

    nist_sha384_single_digest = v(
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
        0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
        0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
        0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7
    )

    nist_sha512_single_digest = v(
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49,
        0xae, 0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a,
        0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f
    )

    # "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    # "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    nist_1024_double = v(
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x62, 0x63, 0x64, 0x65,
        0x66, 0x67, 0x68, 0x69, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x65, 0x66, 0x67, 0x68,
        0x69, 0x6a, 0x6b, 0x6c, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d,
        0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x68, 0x69, 0x6a, 0x6b,
        0x6c, 0x6d, 0x6e, 0x6f, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
        0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x6b, 0x6c, 0x6d, 0x6e,
        0x6f, 0x70, 0x71, 0x72, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
        0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x6e, 0x6f, 0x70, 0x71,
        0x72, 0x73, 0x74, 0x75
    )

    nist_sha512_224_double_digest = v(
        0x23, 0xfe, 0xc5, 0xbb, 0x94, 0xd6, 0x0b, 0x23, 0x30, 0x81, 0x92, 0x64,
        0x0b, 0x0c, 0x45, 0x33, 0x35, 0xd6, 0x64, 0x73, 0x4f, 0xe4, 0x0e, 0x72,
        0x68, 0x67, 0x4a, 0xf9
    )

    nist_sha512_256_double_digest = v(
        0x39, 0x28, 0xe1, 0x84, 0xfb, 0x86, 0x90, 0xf8, 0x40, 0xda, 0x39, 0x88,
        0x12, 0x1d, 0x31, 0xbe, 0x65, 0xcb, 0x9d, 0x3e, 0xf8, 0x3e, 0xe6, 0x14,
        0x6f, 0xea, 0xc8, 0x61, 0xe1, 0x9b, 0x56, 0x3a
    )

    nist_sha384_double_digest = v(
        0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7,
        0x82, 0xcd, 0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
        0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a,
        0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39
    )

    nist_sha512_double_digest = v(
        0x8e, 0x95, 0x9b, 0x75, 0xda, 0xe3, 0x13, 0xda, 0x8c, 0xf4, 0xf7, 0x28,
        0x14, 0xfc, 0x14, 0x3f, 0x8f, 0x77, 0x79, 0xc6, 0xeb, 0x9f, 0x7f, 0xa1,
        0x72, 0x99, 0xae, 0xad, 0xb6, 0x88, 0x90, 0x18, 0x50, 0x1d, 0x28, 0x9e,
        0x49, 0x00, 0xf7, 0xe4, 0x33, 0x1b, 0x99, 0xde, 0xc4, 0xb5, 0x43, 0x3a,
        0xc7, 0xd3, 0x29, 0xee, 0xb6, 0xdd, 0x26, 0x54, 0x5e, 0x96, 0xe5, 0x5b,
        0x87, 0x4b, 0xe9, 0x09
    )

    # HMAC-SHA-1 test cases from RFC 2202.

    hmac_sha1_tc_1_key = v(
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    )

    # "Hi There"
    hmac_sha1_tc_1_data = v(
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    )

    hmac_sha1_tc_1_result_sha1 = v(
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6,
        0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
    )

    # "Jefe"
    hmac_sha1_tc_2_key = v(
        0x4a, 0x65, 0x66, 0x65
    )

    # "what do ya want for nothing?"
    hmac_sha1_tc_2_data = v(
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
        0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
        0x69, 0x6e, 0x67, 0x3f
    )

    hmac_sha1_tc_2_result_sha1 = v(
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5,
        0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79
    )

    hmac_sha1_tc_3_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    hmac_sha1_tc_3_data = v(
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd
    )

    hmac_sha1_tc_3_result_sha1 = v(
        0x12, 0x5d, 0x73, 0x42, 0xb9, 0xac, 0x11, 0xcd, 0x91, 0xa3, 0x9a, 0xf4,
        0x8a, 0xa1, 0x7b, 0x4f, 0x63, 0xf1, 0x75, 0xd3
    )

    hmac_sha1_tc_4_key = v(
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
    )

    hmac_sha1_tc_4_data = v(
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd
    )

    hmac_sha1_tc_4_result_sha1 = v(
        0x4c, 0x90, 0x07, 0xf4, 0x02, 0x62, 0x50, 0xc6, 0xbc, 0x84, 0x14, 0xf9,
        0xbf, 0x50, 0xc8, 0x6c, 0x2d, 0x72, 0x35, 0xda
    )

    hmac_sha1_tc_5_key = v(
        0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
        0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
    )

    # "Test With Truncation"
    hmac_sha1_tc_5_data = v(
        0x54, 0x65, 0x73, 0x74, 0x20, 0x57, 0x69, 0x74, 0x68, 0x20, 0x54, 0x72,
        0x75, 0x6e, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e
    )

    hmac_sha1_tc_5_result_sha1 = v(
        0x4c, 0x1a, 0x03, 0x42, 0x4b, 0x55, 0xe0, 0x7f, 0xe7, 0xf2, 0x7b, 0xe1,
        0xd5, 0x8b, 0xb9, 0x32, 0x4a, 0x9a, 0x5a, 0x04
    )

    hmac_sha1_tc_6_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    # "Test Using Larger Than Block-Size Key - Hash Key First"
    hmac_sha1_tc_6_data = v(
        0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
        0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
        0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
        0x20, 0x46, 0x69, 0x72, 0x73, 0x74
    )

    hmac_sha1_tc_6_result_sha1 = v(
        0xaa, 0x4a, 0xe5, 0xe1, 0x52, 0x72, 0xd0, 0x0e, 0x95, 0x70, 0x56, 0x37,
        0xce, 0x8a, 0x3b, 0x55, 0xed, 0x40, 0x21, 0x12
    )

    hmac_sha1_tc_7_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    # "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
    hmac_sha1_tc_7_data = v(
        0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
        0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
        0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x4c, 0x61, 0x72, 0x67, 0x65, 0x72,
        0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x4f, 0x6e, 0x65, 0x20, 0x42, 0x6c,
        0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x44, 0x61, 0x74, 0x61
    )

    hmac_sha1_tc_7_result_sha1 = v(
        0xe8, 0xe9, 0x9d, 0x0f, 0x45, 0x23, 0x7d, 0x78, 0x6d, 0x6b, 0xba, 0xa7,
        0x96, 0x5c, 0x78, 0x08, 0xbb, 0xff, 0x1a, 0x91
    )

    # HMAC-SHA-2 test cases from RFC 4231.

    hmac_sha2_tc_1_key = v(
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    )

    # "Hi There"
    hmac_sha2_tc_1_data = v(
        0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65
    )

    hmac_sha2_tc_1_result_sha256 = v(
        0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce,
        0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
        0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    )

    hmac_sha2_tc_1_result_sha384 = v(
        0xaf, 0xd0, 0x39, 0x44, 0xd8, 0x48, 0x95, 0x62, 0x6b, 0x08, 0x25, 0xf4,
        0xab, 0x46, 0x90, 0x7f, 0x15, 0xf9, 0xda, 0xdb, 0xe4, 0x10, 0x1e, 0xc6,
        0x82, 0xaa, 0x03, 0x4c, 0x7c, 0xeb, 0xc5, 0x9c, 0xfa, 0xea, 0x9e, 0xa9,
        0x07, 0x6e, 0xde, 0x7f, 0x4a, 0xf1, 0x52, 0xe8, 0xb2, 0xfa, 0x9c, 0xb6
    )

    hmac_sha2_tc_1_result_sha512 = v(
        0x87, 0xaa, 0x7c, 0xde, 0xa5, 0xef, 0x61, 0x9d, 0x4f, 0xf0, 0xb4, 0x24,
        0x1a, 0x1d, 0x6c, 0xb0, 0x23, 0x79, 0xf4, 0xe2, 0xce, 0x4e, 0xc2, 0x78,
        0x7a, 0xd0, 0xb3, 0x05, 0x45, 0xe1, 0x7c, 0xde, 0xda, 0xa8, 0x33, 0xb7,
        0xd6, 0xb8, 0xa7, 0x02, 0x03, 0x8b, 0x27, 0x4e, 0xae, 0xa3, 0xf4, 0xe4,
        0xbe, 0x9d, 0x91, 0x4e, 0xeb, 0x61, 0xf1, 0x70, 0x2e, 0x69, 0x6c, 0x20,
        0x3a, 0x12, 0x68, 0x54
    )

    # "Jefe"
    hmac_sha2_tc_2_key = v(
        0x4a, 0x65, 0x66, 0x65
    )

    # "what do ya want for nothing?"
    hmac_sha2_tc_2_data = v(
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6f, 0x20, 0x79, 0x61, 0x20, 0x77,
        0x61, 0x6e, 0x74, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x6e, 0x6f, 0x74, 0x68,
        0x69, 0x6e, 0x67, 0x3f
    )

    hmac_sha2_tc_2_result_sha256 = v(
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26,
        0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    )

    hmac_sha2_tc_2_result_sha384 = v(
        0xaf, 0x45, 0xd2, 0xe3, 0x76, 0x48, 0x40, 0x31, 0x61, 0x7f, 0x78, 0xd2,
        0xb5, 0x8a, 0x6b, 0x1b, 0x9c, 0x7e, 0xf4, 0x64, 0xf5, 0xa0, 0x1b, 0x47,
        0xe4, 0x2e, 0xc3, 0x73, 0x63, 0x22, 0x44, 0x5e, 0x8e, 0x22, 0x40, 0xca,
        0x5e, 0x69, 0xe2, 0xc7, 0x8b, 0x32, 0x39, 0xec, 0xfa, 0xb2, 0x16, 0x49
    )

    hmac_sha2_tc_2_result_sha512 = v(
        0x16, 0x4b, 0x7a, 0x7b, 0xfc, 0xf8, 0x19, 0xe2, 0xe3, 0x95, 0xfb, 0xe7,
        0x3b, 0x56, 0xe0, 0xa3, 0x87, 0xbd, 0x64, 0x22, 0x2e, 0x83, 0x1f, 0xd6,
        0x10, 0x27, 0x0c, 0xd7, 0xea, 0x25, 0x05, 0x54, 0x97, 0x58, 0xbf, 0x75,
        0xc0, 0x5a, 0x99, 0x4a, 0x6d, 0x03, 0x4f, 0x65, 0xf8, 0xf0, 0xe6, 0xfd,
        0xca, 0xea, 0xb1, 0xa3, 0x4d, 0x4a, 0x6b, 0x4b, 0x63, 0x6e, 0x07, 0x0a,
        0x38, 0xbc, 0xe7, 0x37
    )

    hmac_sha2_tc_3_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    hmac_sha2_tc_3_data = v(
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
        0xdd, 0xdd
    )

    hmac_sha2_tc_3_result_sha256 = v(
        0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb,
        0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
        0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
    )

    hmac_sha2_tc_3_result_sha384 = v(
        0x88, 0x06, 0x26, 0x08, 0xd3, 0xe6, 0xad, 0x8a, 0x0a, 0xa2, 0xac, 0xe0,
        0x14, 0xc8, 0xa8, 0x6f, 0x0a, 0xa6, 0x35, 0xd9, 0x47, 0xac, 0x9f, 0xeb,
        0xe8, 0x3e, 0xf4, 0xe5, 0x59, 0x66, 0x14, 0x4b, 0x2a, 0x5a, 0xb3, 0x9d,
        0xc1, 0x38, 0x14, 0xb9, 0x4e, 0x3a, 0xb6, 0xe1, 0x01, 0xa3, 0x4f, 0x27
    )

    hmac_sha2_tc_3_result_sha512 = v(
        0xfa, 0x73, 0xb0, 0x08, 0x9d, 0x56, 0xa2, 0x84, 0xef, 0xb0, 0xf0, 0x75,
        0x6c, 0x89, 0x0b, 0xe9, 0xb1, 0xb5, 0xdb, 0xdd, 0x8e, 0xe8, 0x1a, 0x36,
        0x55, 0xf8, 0x3e, 0x33, 0xb2, 0x27, 0x9d, 0x39, 0xbf, 0x3e, 0x84, 0x82,
        0x79, 0xa7, 0x22, 0xc8, 0x06, 0xb4, 0x85, 0xa4, 0x7e, 0x67, 0xc8, 0x07,
        0xb9, 0x46, 0xa3, 0x37, 0xbe, 0xe8, 0x94, 0x26, 0x74, 0x27, 0x88, 0x59,
        0xe1, 0x32, 0x92, 0xfb
    )

    hmac_sha2_tc_4_key = v(
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
    )

    hmac_sha2_tc_4_data = v(
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd,
        0xcd, 0xcd
    )

    hmac_sha2_tc_4_result_sha256 = v(
        0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98,
        0x99, 0xf2, 0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07,
        0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b
    )

    hmac_sha2_tc_4_result_sha384 = v(
        0x3e, 0x8a, 0x69, 0xb7, 0x78, 0x3c, 0x25, 0x85, 0x19, 0x33, 0xab, 0x62,
        0x90, 0xaf, 0x6c, 0xa7, 0x7a, 0x99, 0x81, 0x48, 0x08, 0x50, 0x00, 0x9c,
        0xc5, 0x57, 0x7c, 0x6e, 0x1f, 0x57, 0x3b, 0x4e, 0x68, 0x01, 0xdd, 0x23,
        0xc4, 0xa7, 0xd6, 0x79, 0xcc, 0xf8, 0xa3, 0x86, 0xc6, 0x74, 0xcf, 0xfb
    )

    hmac_sha2_tc_4_result_sha512 = v(
        0xb0, 0xba, 0x46, 0x56, 0x37, 0x45, 0x8c, 0x69, 0x90, 0xe5, 0xa8, 0xc5,
        0xf6, 0x1d, 0x4a, 0xf7, 0xe5, 0x76, 0xd9, 0x7f, 0xf9, 0x4b, 0x87, 0x2d,
        0xe7, 0x6f, 0x80, 0x50, 0x36, 0x1e, 0xe3, 0xdb, 0xa9, 0x1c, 0xa5, 0xc1,
        0x1a, 0xa2, 0x5e, 0xb4, 0xd6, 0x79, 0x27, 0x5c, 0xc5, 0x78, 0x80, 0x63,
        0xa5, 0xf1, 0x97, 0x41, 0x12, 0x0c, 0x4f, 0x2d, 0xe2, 0xad, 0xeb, 0xeb,
        0x10, 0xa2, 0x98, 0xdd
    )

    # Skipping HMAC-SHA-2 test case 5.

    hmac_sha2_tc_6_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    # "Test Using Larger Than Block-Size Key - Hash Key First"
    hmac_sha2_tc_6_data = v(
        0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x4c,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x54, 0x68, 0x61, 0x6e, 0x20, 0x42,
        0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x53, 0x69, 0x7a, 0x65, 0x20, 0x4b, 0x65,
        0x79, 0x20, 0x2d, 0x20, 0x48, 0x61, 0x73, 0x68, 0x20, 0x4b, 0x65, 0x79,
        0x20, 0x46, 0x69, 0x72, 0x73, 0x74
    )

    hmac_sha2_tc_6_result_sha256 = v(
        0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa,
        0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
        0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
    )

    hmac_sha2_tc_6_result_sha384 = v(
        0x4e, 0xce, 0x08, 0x44, 0x85, 0x81, 0x3e, 0x90, 0x88, 0xd2, 0xc6, 0x3a,
        0x04, 0x1b, 0xc5, 0xb4, 0x4f, 0x9e, 0xf1, 0x01, 0x2a, 0x2b, 0x58, 0x8f,
        0x3c, 0xd1, 0x1f, 0x05, 0x03, 0x3a, 0xc4, 0xc6, 0x0c, 0x2e, 0xf6, 0xab,
        0x40, 0x30, 0xfe, 0x82, 0x96, 0x24, 0x8d, 0xf1, 0x63, 0xf4, 0x49, 0x52
    )

    hmac_sha2_tc_6_result_sha512 = v(
        0x80, 0xb2, 0x42, 0x63, 0xc7, 0xc1, 0xa3, 0xeb, 0xb7, 0x14, 0x93, 0xc1,
        0xdd, 0x7b, 0xe8, 0xb4, 0x9b, 0x46, 0xd1, 0xf4, 0x1b, 0x4a, 0xee, 0xc1,
        0x12, 0x1b, 0x01, 0x37, 0x83, 0xf8, 0xf3, 0x52, 0x6b, 0x56, 0xd0, 0x37,
        0xe0, 0x5f, 0x25, 0x98, 0xbd, 0x0f, 0xd2, 0x21, 0x5d, 0x6a, 0x1e, 0x52,
        0x95, 0xe6, 0x4f, 0x73, 0xf6, 0x3f, 0x0a, 0xec, 0x8b, 0x91, 0x5a, 0x98,
        0x5d, 0x78, 0x65, 0x98
    )

    hmac_sha2_tc_7_key = v(
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa
    )

    # "This is a test using a larger than block-size key and a larger than block-size data."
    # " The key needs to be hashed before being used by the HMAC algorithm."
    hmac_sha2_tc_7_data = v(
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65,
        0x73, 0x74, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x61, 0x20, 0x6c,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62,
        0x6c, 0x6f, 0x63, 0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x6b, 0x65,
        0x79, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x61, 0x20, 0x6c, 0x61, 0x72, 0x67,
        0x65, 0x72, 0x20, 0x74, 0x68, 0x61, 0x6e, 0x20, 0x62, 0x6c, 0x6f, 0x63,
        0x6b, 0x2d, 0x73, 0x69, 0x7a, 0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x2e,
        0x20, 0x54, 0x68, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x6e, 0x65, 0x65,
        0x64, 0x73, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x65, 0x20, 0x68, 0x61, 0x73,
        0x68, 0x65, 0x64, 0x20, 0x62, 0x65, 0x66, 0x6f, 0x72, 0x65, 0x20, 0x62,
        0x65, 0x69, 0x6e, 0x67, 0x20, 0x75, 0x73, 0x65, 0x64, 0x20, 0x62, 0x79,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x48, 0x4d, 0x41, 0x43, 0x20, 0x61, 0x6c,
        0x67, 0x6f, 0x72, 0x69, 0x74, 0x68, 0x6d, 0x2e
    )

    hmac_sha2_tc_7_result_sha256 = v(
        0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc,
        0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93,
        0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2
    )

    hmac_sha2_tc_7_result_sha384 = v(
        0x66, 0x17, 0x17, 0x8e, 0x94, 0x1f, 0x02, 0x0d, 0x35, 0x1e, 0x2f, 0x25,
        0x4e, 0x8f, 0xd3, 0x2c, 0x60, 0x24, 0x20, 0xfe, 0xb0, 0xb8, 0xfb, 0x9a,
        0xdc, 0xce, 0xbb, 0x82, 0x46, 0x1e, 0x99, 0xc5, 0xa6, 0x78, 0xcc, 0x31,
        0xe7, 0x99, 0x17, 0x6d, 0x38, 0x60, 0xe6, 0x11, 0x0c, 0x46, 0x52, 0x3e
    )

    hmac_sha2_tc_7_result_sha512 = v(
        0xe3, 0x7b, 0x6a, 0x77, 0x5d, 0xc8, 0x7d, 0xba, 0xa4, 0xdf, 0xa9, 0xf9,
        0x6e, 0x5e, 0x3f, 0xfd, 0xde, 0xbd, 0x71, 0xf8, 0x86, 0x72, 0x89, 0x86,
        0x5d, 0xf5, 0xa3, 0x2d, 0x20, 0xcd, 0xc9, 0x44, 0xb6, 0x02, 0x2c, 0xac,
        0x3c, 0x49, 0x82, 0xb1, 0x0d, 0x5e, 0xeb, 0x55, 0xc3, 0xe4, 0xde, 0x15,
        0x13, 0x46, 0x76, 0xfb, 0x6d, 0xe0, 0x44, 0x60, 0x65, 0xc9, 0x74, 0x40,
        0xfa, 0x8c, 0x6a, 0x58
    )

    def t(self, alg, data, expect, key = None):
        h = hsm.hash_initialize(alg, key = key, mixed_mode = False)
        h.update(data)
        result = h.finalize()
        self.assertEqual(result, expect)

    def test_nist_sha1_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.nist_512_single, self.nist_sha1_single_digest)

    def test_nist_sha1_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.nist_512_double, self.nist_sha1_double_digest)

    def test_nist_sha256_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.nist_512_single, self.nist_sha256_single_digest)

    def test_nist_sha256_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.nist_512_double, self.nist_sha256_double_digest)

    def test_nist_sha512_224_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512_224, self.nist_1024_single, self.nist_sha512_224_single_digest)

    def test_nist_sha512_224_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512_224, self.nist_1024_double, self.nist_sha512_224_double_digest)

    def test_nist_sha512_256_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512_256, self.nist_1024_single, self.nist_sha512_256_single_digest)

    def test_nist_sha512_256_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512_256, self.nist_1024_double, self.nist_sha512_256_double_digest)

    def test_nist_sha384_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.nist_1024_single, self.nist_sha384_single_digest)

    def test_nist_sha384_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.nist_1024_double, self.nist_sha384_double_digest)

    def test_nist_sha512_single(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.nist_1024_single, self.nist_sha512_single_digest)

    def test_nist_sha512_double(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.nist_1024_double, self.nist_sha512_double_digest)


    def test_hmac_sha1_tc_1(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_1_data, self.hmac_sha1_tc_1_result_sha1, self.hmac_sha1_tc_1_key)

    def test_hmac_sha1_tc_2(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_2_data, self.hmac_sha1_tc_2_result_sha1, self.hmac_sha1_tc_2_key)

    def test_hmac_sha1_tc_3(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_3_data, self.hmac_sha1_tc_3_result_sha1, self.hmac_sha1_tc_3_key)

    def test_hmac_sha1_tc_4(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_4_data, self.hmac_sha1_tc_4_result_sha1, self.hmac_sha1_tc_4_key)

    def test_hmac_sha1_tc_5(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_5_data, self.hmac_sha1_tc_5_result_sha1, self.hmac_sha1_tc_5_key)

    def test_hmac_sha1_tc_6(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_6_data, self.hmac_sha1_tc_6_result_sha1, self.hmac_sha1_tc_6_key)

    def test_hmac_sha1_tc_7(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA1, self.hmac_sha1_tc_7_data, self.hmac_sha1_tc_7_result_sha1, self.hmac_sha1_tc_7_key)


    def test_hmac_sha256_tc_1(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_1_data, self.hmac_sha2_tc_1_result_sha256, self.hmac_sha2_tc_1_key)

    def test_hmac_sha256_tc_2(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_2_data, self.hmac_sha2_tc_2_result_sha256, self.hmac_sha2_tc_2_key)

    def test_hmac_sha256_tc_3(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_3_data, self.hmac_sha2_tc_3_result_sha256, self.hmac_sha2_tc_3_key)

    def test_hmac_sha256_tc_4(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_4_data, self.hmac_sha2_tc_4_result_sha256, self.hmac_sha2_tc_4_key)

    def test_hmac_sha256_tc_6(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_6_data, self.hmac_sha2_tc_6_result_sha256, self.hmac_sha2_tc_6_key)

    def test_hmac_sha256_tc_7(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA256, self.hmac_sha2_tc_7_data, self.hmac_sha2_tc_7_result_sha256, self.hmac_sha2_tc_7_key)


    def test_hmac_sha384_tc_1(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_1_data, self.hmac_sha2_tc_1_result_sha384, self.hmac_sha2_tc_1_key)

    def test_hmac_sha384_tc_2(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_2_data, self.hmac_sha2_tc_2_result_sha384, self.hmac_sha2_tc_2_key)

    def test_hmac_sha384_tc_3(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_3_data, self.hmac_sha2_tc_3_result_sha384, self.hmac_sha2_tc_3_key)

    def test_hmac_sha384_tc_4(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_4_data, self.hmac_sha2_tc_4_result_sha384, self.hmac_sha2_tc_4_key)

    def test_hmac_sha384_tc_6(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_6_data, self.hmac_sha2_tc_6_result_sha384, self.hmac_sha2_tc_6_key)

    def test_hmac_sha384_tc_7(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA384, self.hmac_sha2_tc_7_data, self.hmac_sha2_tc_7_result_sha384, self.hmac_sha2_tc_7_key)


    def test_hmac_sha512_tc_1(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_1_data, self.hmac_sha2_tc_1_result_sha512, self.hmac_sha2_tc_1_key)

    def test_hmac_sha512_tc_2(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_2_data, self.hmac_sha2_tc_2_result_sha512, self.hmac_sha2_tc_2_key)

    def test_hmac_sha512_tc_3(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_3_data, self.hmac_sha2_tc_3_result_sha512, self.hmac_sha2_tc_3_key)

    def test_hmac_sha512_tc_4(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_4_data, self.hmac_sha2_tc_4_result_sha512, self.hmac_sha2_tc_4_key)

    def test_hmac_sha512_tc_6(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_6_data, self.hmac_sha2_tc_6_result_sha512, self.hmac_sha2_tc_6_key)

    def test_hmac_sha512_tc_7(self):
        self.t(HAL_DIGEST_ALGORITHM_SHA512, self.hmac_sha2_tc_7_data, self.hmac_sha2_tc_7_result_sha512, self.hmac_sha2_tc_7_key)



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

    def sign_verify(self, hashalg, k1, k2, length = 1024):
        h = hsm.hash_initialize(hashalg)
        h.update("Your mother was a hamster")
        data = h.finalize()
        sig = k1.sign(data = data, length = length)
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

    def gen_sign_verify_hashsig(self, L, lms, lmots, length):
        k1 = hsm.pkey_generate_hashsig(L, lms, lmots, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(k1.public_key, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN)
        self.addCleanup(k2.delete)
        self.sign_verify(HAL_DIGEST_ALGORITHM_SHA256, k1, k2, length)

    def test_gen_sign_verify_ecdsa_p256_sha256(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA256, HAL_CURVE_P256)

    def test_gen_sign_verify_ecdsa_p384_sha384(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA384, HAL_CURVE_P384)

    def test_gen_sign_verify_ecdsa_p521_sha512(self):
        self.gen_sign_verify_ecdsa(HAL_DIGEST_ALGORITHM_SHA512, HAL_CURVE_P521)

    def test_gen_sign_verify_rsa_1024_sha256(self):
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA256, 1024)

    def test_gen_sign_verify_rsa_2048_sha384(self):
        self.skipUnlessAll("Slow")
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA384, 2048)

    def test_gen_sign_verify_rsa_4096_sha512(self):
        self.skipUnlessAll("Hideously slow")
        self.gen_sign_verify_rsa(HAL_DIGEST_ALGORITHM_SHA512, 4096)

    def test_gen_unsupported_length(self):
        with self.assertRaises(HAL_ERROR_BAD_ARGUMENTS):
            hsm.pkey_generate_rsa(1028).delete()

    def test_gen_sign_verify_hashsig_L1_h5_w4(self):
        self.gen_sign_verify_hashsig(1, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W4, 2352)

    def test_gen_sign_verify_hashsig_L2_h5_w2(self):
        self.gen_sign_verify_hashsig(2, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W2, 8980)


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

    def gen_sign_verify_hashsig(self, L, lms, lmots, length, method):
        k1 = hsm.pkey_generate_hashsig(L, lms, lmots, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN)
        self.addCleanup(k1.delete)
        k2 = hsm.pkey_load(k1.public_key, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE | HAL_KEY_FLAG_TOKEN)
        self.addCleanup(k2.delete)
        method(HAL_DIGEST_ALGORITHM_SHA256, k1, k2, length)

    @staticmethod
    def h(alg, mixed_mode = False):
        h = hsm.hash_initialize(alg, mixed_mode = mixed_mode)
        h.update("Your mother was a hamster")
        return h

    def sign_verify_data(self, alg, k1, k2, length = 1024):
        data = self.h(alg, mixed_mode = True).finalize()
        sig = k1.sign(data = data, length = length)
        k1.verify(signature = sig, data = data)
        k2.verify(signature = sig, data = data)

    def sign_verify_remote_remote(self, alg, k1, k2, length = 1024):
        sig = k1.sign(hash = self.h(alg, mixed_mode = False), length = length)
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = False))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = False))

    def sign_verify_remote_local(self, alg, k1, k2, length = 1024):
        sig = k1.sign(hash = self.h(alg, mixed_mode = False), length = length)
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = True))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = True))

    def sign_verify_local_remote(self, alg, k1, k2, length = 1024):
        sig = k1.sign(hash = self.h(alg, mixed_mode = True), length = length)
        k1.verify(signature = sig, hash = self.h(alg, mixed_mode = False))
        k2.verify(signature = sig, hash = self.h(alg, mixed_mode = False))

    def sign_verify_local_local(self, alg, k1, k2, length = 1024):
        sig = k1.sign(hash = self.h(alg, mixed_mode = True), length = length)
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

    def test_gen_sign_verify_hashsig_L1_h5_w4_remote_remote(self):
        self.gen_sign_verify_hashsig(1, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W4, 2352, self.sign_verify_remote_remote)

    def test_gen_sign_verify_hashsig_L1_h5_w4_remote_local(self):
        self.gen_sign_verify_hashsig(1, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W4, 2352, self.sign_verify_remote_local)

    def test_gen_sign_verify_hashsig_L1_h5_w4_local_remote(self):
        self.gen_sign_verify_hashsig(1, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W4, 2352, self.sign_verify_local_remote)

    def test_gen_sign_verify_hashsig_L1_h5_w4_local_local(self):
        self.gen_sign_verify_hashsig(1, HAL_LMS_SHA256_N32_H5, HAL_LMOTS_SHA256_N32_W4, 2352, self.sign_verify_local_local)


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


class TestPKeyHashsigInterop(TestCaseLoggedIn):

    def load_verify_hashsig(self, key, msg, sig):
        k = hsm.pkey_load(key, HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE)
        self.addCleanup(k.delete)
        k.verify(signature = sig, data = msg)

    def test_interop_hashsig_tc1(self):
        self.load_verify_hashsig(hashsig_tc1_key, hashsig_tc1_msg, hashsig_tc1_sig)

    def test_interop_hashsig_tc2(self):
        self.load_verify_hashsig(hashsig_tc2_key, hashsig_tc2_msg, hashsig_tc2_sig)


class TestPKeyMatch(TestCaseLoggedIn):
    """
    Tests involving PKey list and match functions.
    """

    @staticmethod
    def key_flag_names(flags):
        names = dict(digitalsignature = HAL_KEY_FLAG_USAGE_DIGITALSIGNATURE,
                     keyencipherment  = HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT,
                     dataencipherment = HAL_KEY_FLAG_USAGE_DATAENCIPHERMENT,
                     token            = HAL_KEY_FLAG_TOKEN,
                     public           = HAL_KEY_FLAG_PUBLIC,
                     exportable       = HAL_KEY_FLAG_EXPORTABLE)
        return ", ".join(sorted(k for k, v in names.iteritems() if (flags & v) != 0))

    @staticmethod
    def cleanup_key(uuid):
        try:
            with hsm.pkey_open(uuid) as pkey:
                pkey.delete()
        except Exception as e:
            logger.debug("Problem deleting key %s: %s", uuid, e)

    def load_keys(self, flags):
        uuids = set()
        for obj in PreloadedKey.db.itervalues():
            with hsm.pkey_load(obj.der, flags) as k:
                self.addCleanup(self.cleanup_key, k.uuid)
                uuids.add(k.uuid)
                #print k.uuid, k.key_type, k.key_curve, self.key_flag_names(k.key_flags)
                k.set_attributes(dict((i, a) for i, a in enumerate((str(obj.keytype), str(obj.fn2)))))
        return uuids

    def match(self, uuids, **kwargs):
        n = 0
        for uuid in hsm.pkey_match(**kwargs):
            if uuid in uuids:
                with hsm.pkey_open(uuid) as k:
                    n += 1
                    yield n, k

    def ks_match(self, mask, flags):
        tags  = []
        uuids = set()
        for i in xrange(2):
            uuids |= self.load_keys(flags if mask else HAL_KEY_FLAG_TOKEN * i)
            tags.extend(PreloadedKey.db)
        self.assertEqual(len(tags), len(uuids))

        n = 0
        self.assertEqual(uuids, set(k.uuid for n, k in self.match(mask  = mask,
                                                                  flags = flags,
                                                                  uuids = uuids)))

        for keytype in set(HALKeyType.index.itervalues()) - {HAL_KEY_TYPE_NONE}:
            n = 0
            for n, k in self.match(mask = mask, flags = flags, uuids = uuids, type = keytype):
                self.assertEqual(k.key_type, keytype)
                self.assertEqual(k.get_attributes({0}).pop(0), str(keytype))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t1 == keytype))

        for curve in set(HALCurve.index.itervalues()) - {HAL_CURVE_NONE}:
            n = 0
            for n, k in self.match(mask = mask, flags = flags, uuids = uuids, curve = curve):
                self.assertEqual(k.key_curve, curve)
                self.assertEqual(k.get_attributes({1}).pop(1), str(curve))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_EC_PUBLIC,
                                           HAL_KEY_TYPE_EC_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags if t2 == curve))

        for keylen in set(kl for kt, kl in tags if not isinstance(kl, Enum)):
            n = 0
            for n, k in self.match(mask = mask, flags = flags, uuids = uuids,
                                   attributes = {1 : str(keylen)}):
                self.assertEqual(keylen, int(k.get_attributes({1}).pop(1)))
                self.assertIn(k.key_type, (HAL_KEY_TYPE_RSA_PUBLIC,
                                           HAL_KEY_TYPE_RSA_PRIVATE))
            self.assertEqual(n, sum(1 for t1, t2 in tags
                                    if not isinstance(t2, Enum) and  t2 == keylen))

        n = 0
        for n, k in self.match(mask = mask, flags = flags, uuids = uuids,
                               type = HAL_KEY_TYPE_RSA_PUBLIC, attributes = {1 : "2048"}):
            self.assertEqual(k.key_type, HAL_KEY_TYPE_RSA_PUBLIC)
        self.assertEqual(n, sum(1 for t1, t2 in tags
                                if t1 == HAL_KEY_TYPE_RSA_PUBLIC and t2 == 2048))

    def test_ks_match_token(self):
        self.ks_match(mask = HAL_KEY_FLAG_TOKEN, flags = HAL_KEY_FLAG_TOKEN)

    def test_ks_match_volatile(self):
        self.ks_match(mask = HAL_KEY_FLAG_TOKEN, flags = 0)

    def test_ks_match_all(self):
        self.ks_match(mask = 0, flags = 0)


class TestPKeyAttribute(TestCaseLoggedIn):
    """
    Attribute creation/lookup/deletion tests.
    """

    @staticmethod
    def cleanup_key(uuid):
        try:
            with hsm.pkey_open(uuid) as pkey:
                pkey.delete()
        except Exception as e:
            logger.debug("Problem deleting key %s: %s", uuid, e)

    def load_and_fill(self, flags, n_keys = 1, n_attrs = 2, n_fill = 0):
        pinwheel = Pinwheel()
        for i in xrange(n_keys):
            for obj in PreloadedKey.db.itervalues():
                with hsm.pkey_load(obj.der, flags) as k:
                    pinwheel()
                    self.addCleanup(self.cleanup_key, k.uuid)
                    k.set_attributes(dict((j, "Attribute {}{}".format(j, "*" * n_fill))
                                          for j in xrange(n_attrs)))
                    pinwheel()

    # These sizes work with a 8192-byte keystore block; if you tweak
    # the underlying block size, you may need to tweak these tests too.

    def test_attribute_svelt_volatile_many(self):
        self.load_and_fill(0, n_attrs = 64)

    def test_attribute_bloat_volatile_many(self):
        self.load_and_fill(0, n_attrs = 128)

    def test_attribute_svelt_volatile_big(self):
        self.load_and_fill(0, n_attrs = 6, n_fill = 256)

    def test_attribute_bloat_volatile_big(self):
        self.load_and_fill(0, n_attrs = 6, n_fill = 512)

    def test_attribute_svelt_token_many(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 64)

    def test_attribute_bloat_token_many(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 128)

    def test_attribute_svelt_token_big(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 6, n_fill = 256)

    def test_attribute_bloat_token_big(self):
        self.load_and_fill(HAL_KEY_FLAG_TOKEN, n_attrs = 6, n_fill = 512)


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
        algorithm = DerObjectId()
        encryptedData = DerOctetString()
        encryptionAlgorithm.decode(encryptedPrivateKeyInfo[0])
        # <kludge>
        # Sigh, bugs in PyCrypto ASN.1 code.  Should do:
        #
        #algorithm.decode(encryptionAlgorithm[0])
        #encryptedData.decode(encryptedPrivateKeyInfo[1])
        #
        # but due to bugs in those methods we must instead do:
        DerObject.decode(algorithm, encryptionAlgorithm[0])
        DerObject.decode(encryptedData, encryptedPrivateKeyInfo[1])
        # </kludge>
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

    @staticmethod
    def _xor(R0, t):
        return pack(">Q", unpack(">Q", R0)[0] ^ t)

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
                    R[0] = self._xor(R[0], n * j + i)
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
                    R[0] = self._xor(R[0], n * j + i)
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
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQDNalhJC34OtQ0j
4QlP+Sj3bAzY858Weabcpzfiea4rqx7PQMmv1WJv1HkrjpE2CpxR0Ch2NTpzLf8x
kDndKo/tHBH8tC1aYrZr5PiJ7La9BnSIIMDY0jiCOCYICNmc4P+bnJReMKKD/Any
kZeiWDygee914uDWOgg5IX0650usjpomcOA5916DOYJZeZaXtNeuodUhZmFlkXup
BlGyjplDX/yaOm9UPR2sBIHEycjO+l7jKetjY0HzTtf8PlttJynb3ZkpM1/m6c83
VKwXLnKbN8tmt82Sxh5/rE9dxWvo6I5uLj0N7x7XVo0+Pp+AvPOoC7WuOOsOSC9f
HkbuA8lerVqrq7EHZwoytFL6K+bILy9CXM+VDBbbShh5458KDt100Aly7eM1O40l
pl2Fz2zOlWFXwNdmhd79HNQ2NkfvBSq54fJ+lsvBL6HcxwmqttYV0JAGK9megjTl
wXYkgcR5HdLQbKjb8iF414VfZO3ygOcdjhqiVEeJHkIx0zxSgZLFH1jXZ9n11yp0
Ifd3rAMCwEMdMITxkjAXCFbqID6DnhgTdfsGWyBavrSmgIOAf4ImOHRUNXGovuv7
DvqwP1YBAxrsZv4ynZcJichk9dOuybBVtn2zm8VdQQ4NiibqoGVtkHyDJnN57lKR
zWPHZ+earFG1+UDhbfFUBAWh/asWJQIDAQABAoICAHGFBclIWp/SGrLrWHQj5Cno
Qqla6V5IWJi0qMO2LzTe2qX6zfsoV8ApkdUqcsGE16K3AMVi4SxqDQ/c/r1lGikV
TDN1d2LuDpZN8bR3Zv3LpXbdcvXgJ25/jTT/fxOdnGTpAW2UPxvlm7G8GCqVzNt6
x4VEnrCFXaoFAeodjMqN/E6mLqSaOlcW3xyHf1vTiyZtNRXCOK0i204rudaNy9Fa
KIUrKf9Jzy4TR4vzX9BSuUGdFwLUBcxqlB5Ib8pAzHc/XbdRNvyr1eJkHr6o4pk5
GmVnymoEpzIzjaDqy5npe10UnJUowsiKgoAVp5xDz/vcjMj9l5lK9zL/zn8XBJ8a
McPsLu8v2R+Dvuej4i8diUFiIiq1N12lAfksYkAmc4a2TTjv86NOYvxDLKW8MC/y
MF5ll1s5fsv7yOTkNseZ9RwOO8FL2D4Vt+SMO6umGunV0ef9iBoDbs1mzztM9ZfV
pU+I6VcSE71IceKIoIcOkHNXWBb96KGjfez64SvntmhqTOic3/M1vsqodQ79kbAy
D5X1tUiBOGpt2CbE3PskXPXgI3v3I+ZblBPU/W/trrFZplMAt7Yca/LQH6JHOEul
rLW0jg7+iY+P29TNUnAYfO1W3RF11yYD3BVjeqCVE2X5i82WboFSfwrA8iqSLwmi
KgDwnURDmbP8rR9uvNw5AoIBAQDxMKqrSluZ/G2x/jbOGxJTDVV1wIgbQhhxJbEi
IJ+6OvIBBfW2ay1l5FyGXKReZ074kNym8zIEoEPvXzwkRaMJfUhFG0fFMnlYb6kT
yw08s0vx5lVn4IRs2NWTh21YYvDI2b6tCQw2Y6Wb7tkd17MFeWNk56plt2xNINBw
ZgbwnGW8ukA3rSmMga9N1Ot2eSwyEHg8r6Xsq3IRUNZdT9VPqSqE/dGLV2ge//zU
GmWB+MQkzxnGZqx8/hKUnWiUqqwcwVKtyWNkIB6YoR7FXLODxweb2CGPowtBl7eC
z3hXqHwjaJ+sEE0cytmBiDYNvQZ7Jiuv6RkYONPQNmnSODJ/AoIBAQDaB1NyWat8
BT/rvOI4luOQyB+EF214TUFskM1RxrTMHqom7gHA2C3RzEcxuW2ATb/yFY/3kchp
B2HWYiDBIr3czFFtoC8BB8Xea4nG8xHkyu4N6MT4gQr15l62CQ0cZbJ+IXMFYd1r
9n09CSpi1F+inmoUFUA9nhjNHmFPSPrh4NA3/P0LRkHpEv0RxcmARiAYjfA/xCyv
DclEFA3RIJVGasQmbhYhez4IQc6Tnr9Vs8y/za7BsdWCFLRT1sRm82h6rtlCNLa1
FddEl46BDII29jLrvRPQq9BmgNvn0RsQNLN5BlLUnusMQEdb5XBFIkDyegwSBl0S
/wDFsQXYJ11bAoIBAAzAfvWJe+hbUU1s3GbvRXvAo7kTEd8nEnXBAWmFggxtm2f0
cbZQWlkdxsqP0VzwZ1t7BT+KciWOd6kLRvm/+MvCpPSKabQCZCoJ1U2nma6Q6D4E
6JUSaM38dOZU7bIToRltcchiRxQFFrd03GPYiK2ManXmTbsNBJvbVUnsCwfjrPla
e5S2AhFctfEOhdiAtZZ8Cm9i9gnaUrCZrovGccfBcO8RIGgWmfmxnSN1tdI2XeB4
VquHuCzvnfnfjKz3jRwEGKP5ltivXg7BzgevTAp2lm9l8PhQLYMtS1WONJWl4dJZ
cL+/KOSR0QgpNHpreRE/xmWJlHsUXhaPGe80a28CggEAS7mDqBGw17BTFSNTRuhR
PXXkTFJ+uOvML1LTnPVw0fxMiJzdiwcKUvWqPID0oT1fz0rh59CAVMo1luoaCjpw
ywFDvtmFucvjU27yOWEu89HvgHE6CD15exJ6DqtyHEzOA7TGaDYnW1oPAWXvjMfK
N4bhvPvshfolDwjgL1Nfn5gfeXKqyIGsXrEzqDqT07OHbj/OE7ek9V/KaZS1f87b
ScvHOLm/gf11/BQvFWJrfe6mzG85pRiI2VcrknrjWAZuYT3dQ3tfgeGGFNK2seeQ
SlqUMQBIo48pIJDcz9T2m1hShVRG7IYNiQHCRw6XQcu11wHAs3n2VaSvtfnX181E
RQKCAQEAyTf2T6yEPYNby5sT8uCh+ivB9PbnnwU/Gln6kbAwcvdmcu5C6JE7I/JB
mP9maYsBrZM+vBL+yyWfjpjYp6x6NYr/QerxJoUuE6NpwXy7kg44oFm/H4c5Ppy1
E0FXLO30DzC7QMTqfNzkdCmb1Mxes4u5nQu7bbIWKTCgiBilTqEF1uDWaeKtlL9n
KolX2BYHpljJQBQZ2AGovp65IACoGn3erPyxAt6ypO59PWZVl3+d0vK+MMmM0pQT
TDWD/XE22Do3loz7ulz8PAT+z4S0LFz/znx1BgsEcg9zDp7QV0vedOzjgGkCpwrb
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

# Hashsig test cases. There's no Python version of hashsig, so we're just
# verifying pre-generated signatures from the draft.
#
# I could define a container class for these, but it doesn't really add value.

# draft-mcgrew Test Case 1
hashsig_tc1_key = b'''\
\x30\x53\x30\x0f\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\
\x11\x05\x00\x03\x40\x00\x30\x3d\x02\x01\x02\x02\x01\x05\x02\x01\
\x04\x04\x10\x61\xa5\xd5\x7d\x37\xf5\xe4\x6b\xfb\x75\x20\x80\x6b\
\x07\xa1\xb8\x04\x20\x50\x65\x0e\x3b\x31\xfe\x4a\x77\x3e\xa2\x9a\
\x07\xf0\x9c\xf2\xea\x30\xe5\x79\xf0\xdf\x58\xef\x8e\x29\x8d\xa0\
\x43\x4c\xb2\xb8\x78\
'''
hashsig_tc1_msg = b'''\
\x54\x68\x65\x20\x70\x6f\x77\x65\x72\x73\x20\x6e\x6f\x74\x20\x64\
\x65\x6c\x65\x67\x61\x74\x65\x64\x20\x74\x6f\x20\x74\x68\x65\x20\
\x55\x6e\x69\x74\x65\x64\x20\x53\x74\x61\x74\x65\x73\x20\x62\x79\
\x20\x74\x68\x65\x20\x43\x6f\x6e\x73\x74\x69\x74\x75\x74\x69\x6f\
\x6e\x2c\x20\x6e\x6f\x72\x20\x70\x72\x6f\x68\x69\x62\x69\x74\x65\
\x64\x20\x62\x79\x20\x69\x74\x20\x74\x6f\x20\x74\x68\x65\x20\x53\
\x74\x61\x74\x65\x73\x2c\x20\x61\x72\x65\x20\x72\x65\x73\x65\x72\
\x76\x65\x64\x20\x74\x6f\x20\x74\x68\x65\x20\x53\x74\x61\x74\x65\
\x73\x20\x72\x65\x73\x70\x65\x63\x74\x69\x76\x65\x6c\x79\x2c\x20\
\x6f\x72\x20\x74\x6f\x20\x74\x68\x65\x20\x70\x65\x6f\x70\x6c\x65\
\x2e\x0a\
'''
hashsig_tc1_sig = b'''\
\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x04\xd3\x2b\x56\x67\
\x1d\x7e\xb9\x88\x33\xc4\x9b\x43\x3c\x27\x25\x86\xbc\x4a\x1c\x8a\
\x89\x70\x52\x8f\xfa\x04\xb9\x66\xf9\x42\x6e\xb9\x96\x5a\x25\xbf\
\xd3\x7f\x19\x6b\x90\x73\xf3\xd4\xa2\x32\xfe\xb6\x91\x28\xec\x45\
\x14\x6f\x86\x29\x2f\x9d\xff\x96\x10\xa7\xbf\x95\xa6\x4c\x7f\x60\
\xf6\x26\x1a\x62\x04\x3f\x86\xc7\x03\x24\xb7\x70\x7f\x5b\x4a\x8a\
\x6e\x19\xc1\x14\xc7\xbe\x86\x6d\x48\x87\x78\xa0\xe0\x5f\xd5\xc6\
\x50\x9a\x6e\x61\xd5\x59\xcf\x1a\x77\xa9\x70\xde\x92\x7d\x60\xc7\
\x0d\x3d\xe3\x1a\x7f\xa0\x10\x09\x94\xe1\x62\xa2\x58\x2e\x8f\xf1\
\xb1\x0c\xd9\x9d\x4e\x8e\x41\x3e\xf4\x69\x55\x9f\x7d\x7e\xd1\x2c\
\x83\x83\x42\xf9\xb9\xc9\x6b\x83\xa4\x94\x3d\x16\x81\xd8\x4b\x15\
\x35\x7f\xf4\x8c\xa5\x79\xf1\x9f\x5e\x71\xf1\x84\x66\xf2\xbb\xef\
\x4b\xf6\x60\xc2\x51\x8e\xb2\x0d\xe2\xf6\x6e\x3b\x14\x78\x42\x69\
\xd7\xd8\x76\xf5\xd3\x5d\x3f\xbf\xc7\x03\x9a\x46\x2c\x71\x6b\xb9\
\xf6\x89\x1a\x7f\x41\xad\x13\x3e\x9e\x1f\x6d\x95\x60\xb9\x60\xe7\
\x77\x7c\x52\xf0\x60\x49\x2f\x2d\x7c\x66\x0e\x14\x71\xe0\x7e\x72\
\x65\x55\x62\x03\x5a\xbc\x9a\x70\x1b\x47\x3e\xcb\xc3\x94\x3c\x6b\
\x9c\x4f\x24\x05\xa3\xcb\x8b\xf8\xa6\x91\xca\x51\xd3\xf6\xad\x2f\
\x42\x8b\xab\x6f\x3a\x30\xf5\x5d\xd9\x62\x55\x63\xf0\xa7\x5e\xe3\
\x90\xe3\x85\xe3\xae\x0b\x90\x69\x61\xec\xf4\x1a\xe0\x73\xa0\x59\
\x0c\x2e\xb6\x20\x4f\x44\x83\x1c\x26\xdd\x76\x8c\x35\xb1\x67\xb2\
\x8c\xe8\xdc\x98\x8a\x37\x48\x25\x52\x30\xce\xf9\x9e\xbf\x14\xe7\
\x30\x63\x2f\x27\x41\x44\x89\x80\x8a\xfa\xb1\xd1\xe7\x83\xed\x04\
\x51\x6d\xe0\x12\x49\x86\x82\x21\x2b\x07\x81\x05\x79\xb2\x50\x36\
\x59\x41\xbc\xc9\x81\x42\xda\x13\x60\x9e\x97\x68\xaa\xf6\x5d\xe7\
\x62\x0d\xab\xec\x29\xeb\x82\xa1\x7f\xde\x35\xaf\x15\xad\x23\x8c\
\x73\xf8\x1b\xdb\x8d\xec\x2f\xc0\xe7\xf9\x32\x70\x10\x99\x76\x2b\
\x37\xf4\x3c\x4a\x3c\x20\x01\x0a\x3d\x72\xe2\xf6\x06\xbe\x10\x8d\
\x31\x0e\x63\x9f\x09\xce\x72\x86\x80\x0d\x9e\xf8\xa1\xa4\x02\x81\
\xcc\x5a\x7e\xa9\x8d\x2a\xdc\x7c\x74\x00\xc2\xfe\x5a\x10\x15\x52\
\xdf\x4e\x3c\xcc\xfd\x0c\xbf\x2d\xdf\x5d\xc6\x77\x9c\xbb\xc6\x8f\
\xee\x0c\x3e\xfe\x4e\xc2\x2b\x83\xa2\xca\xa3\xe4\x8e\x08\x09\xa0\
\xa7\x50\xb7\x3c\xcd\xcf\x3c\x79\xe6\x58\x0c\x15\x4f\x8a\x58\xf7\
\xf2\x43\x35\xee\xc5\xc5\xeb\x5e\x0c\xf0\x1d\xcf\x44\x39\x42\x40\
\x95\xfc\xeb\x07\x7f\x66\xde\xd5\xbe\xc7\x3b\x27\xc5\xb9\xf6\x4a\
\x2a\x9a\xf2\xf0\x7c\x05\xe9\x9e\x5c\xf8\x0f\x00\x25\x2e\x39\xdb\
\x32\xf6\xc1\x96\x74\xf1\x90\xc9\xfb\xc5\x06\xd8\x26\x85\x77\x13\
\xaf\xd2\xca\x6b\xb8\x5c\xd8\xc1\x07\x34\x75\x52\xf3\x05\x75\xa5\
\x41\x78\x16\xab\x4d\xb3\xf6\x03\xf2\xdf\x56\xfb\xc4\x13\xe7\xd0\
\xac\xd8\xbd\xd8\x13\x52\xb2\x47\x1f\xc1\xbc\x4f\x1e\xf2\x96\xfe\
\xa1\x22\x04\x03\x46\x6b\x1a\xfe\x78\xb9\x4f\x7e\xcf\x7c\xc6\x2f\
\xb9\x2b\xe1\x4f\x18\xc2\x19\x23\x84\xeb\xce\xaf\x88\x01\xaf\xdf\
\x94\x7f\x69\x8c\xe9\xc6\xce\xb6\x96\xed\x70\xe9\xe8\x7b\x01\x44\
\x41\x7e\x8d\x7b\xaf\x25\xeb\x5f\x70\xf0\x9f\x01\x6f\xc9\x25\xb4\
\xdb\x04\x8a\xb8\xd8\xcb\x2a\x66\x1c\xe3\xb5\x7a\xda\x67\x57\x1f\
\x5d\xd5\x46\xfc\x22\xcb\x1f\x97\xe0\xeb\xd1\xa6\x59\x26\xb1\x23\
\x4f\xd0\x4f\x17\x1c\xf4\x69\xc7\x6b\x88\x4c\xf3\x11\x5c\xce\x6f\
\x79\x2c\xc8\x4e\x36\xda\x58\x96\x0c\x5f\x1d\x76\x0f\x32\xc1\x2f\
\xae\xf4\x77\xe9\x4c\x92\xeb\x75\x62\x5b\x6a\x37\x1e\xfc\x72\xd6\
\x0c\xa5\xe9\x08\xb3\xa7\xdd\x69\xfe\xf0\x24\x91\x50\xe3\xee\xbd\
\xfe\xd3\x9c\xbd\xc3\xce\x97\x04\x88\x2a\x20\x72\xc7\x5e\x13\x52\
\x7b\x7a\x58\x1a\x55\x61\x68\x78\x3d\xc1\xe9\x75\x45\xe3\x18\x65\
\xdd\xc4\x6b\x3c\x95\x78\x35\xda\x25\x2b\xb7\x32\x8d\x3e\xe2\x06\
\x24\x45\xdf\xb8\x5e\xf8\xc3\x5f\x8e\x1f\x33\x71\xaf\x34\x02\x3c\
\xef\x62\x6e\x0a\xf1\xe0\xbc\x01\x73\x51\xaa\xe2\xab\x8f\x5c\x61\
\x2e\xad\x0b\x72\x9a\x1d\x05\x9d\x02\xbf\xe1\x8e\xfa\x97\x1b\x73\
\x00\xe8\x82\x36\x0a\x93\xb0\x25\xff\x97\xe9\xe0\xee\xc0\xf3\xf3\
\xf1\x30\x39\xa1\x7f\x88\xb0\xcf\x80\x8f\x48\x84\x31\x60\x6c\xb1\
\x3f\x92\x41\xf4\x0f\x44\xe5\x37\xd3\x02\xc6\x4a\x4f\x1f\x4a\xb9\
\x49\xb9\xfe\xef\xad\xcb\x71\xab\x50\xef\x27\xd6\xd6\xca\x85\x10\
\xf1\x50\xc8\x5f\xb5\x25\xbf\x25\x70\x3d\xf7\x20\x9b\x60\x66\xf0\
\x9c\x37\x28\x0d\x59\x12\x8d\x2f\x0f\x63\x7c\x7d\x7d\x7f\xad\x4e\
\xd1\xc1\xea\x04\xe6\x28\xd2\x21\xe3\xd8\xdb\x77\xb7\xc8\x78\xc9\
\x41\x1c\xaf\xc5\x07\x1a\x34\xa0\x0f\x4c\xf0\x77\x38\x91\x27\x53\
\xdf\xce\x48\xf0\x75\x76\xf0\xd4\xf9\x4f\x42\xc6\xd7\x6f\x7c\xe9\
\x73\xe9\x36\x70\x95\xba\x7e\x9a\x36\x49\xb7\xf4\x61\xd9\xf9\xac\
\x13\x32\xa4\xd1\x04\x4c\x96\xae\xfe\xe6\x76\x76\x40\x1b\x64\x45\
\x7c\x54\xd6\x5f\xef\x65\x00\xc5\x9c\xdf\xb6\x9a\xf7\xb6\xdd\xdf\
\xcb\x0f\x08\x62\x78\xdd\x8a\xd0\x68\x60\x78\xdf\xb0\xf3\xf7\x9c\
\xd8\x93\xd3\x14\x16\x86\x48\x49\x98\x98\xfb\xc0\xce\xd5\xf9\x5b\
\x74\xe8\xff\x14\xd7\x35\xcd\xea\x96\x8b\xee\x74\x00\x00\x00\x05\
\xd8\xb8\x11\x2f\x92\x00\xa5\xe5\x0c\x4a\x26\x21\x65\xbd\x34\x2c\
\xd8\x00\xb8\x49\x68\x10\xbc\x71\x62\x77\x43\x5a\xc3\x76\x72\x8d\
\x12\x9a\xc6\xed\xa8\x39\xa6\xf3\x57\xb5\xa0\x43\x87\xc5\xce\x97\
\x38\x2a\x78\xf2\xa4\x37\x29\x17\xee\xfc\xbf\x93\xf6\x3b\xb5\x91\
\x12\xf5\xdb\xe4\x00\xbd\x49\xe4\x50\x1e\x85\x9f\x88\x5b\xf0\x73\
\x6e\x90\xa5\x09\xb3\x0a\x26\xbf\xac\x8c\x17\xb5\x99\x1c\x15\x7e\
\xb5\x97\x11\x15\xaa\x39\xef\xd8\xd5\x64\xa6\xb9\x02\x82\xc3\x16\
\x8a\xf2\xd3\x0e\xf8\x9d\x51\xbf\x14\x65\x45\x10\xa1\x2b\x8a\x14\
\x4c\xca\x18\x48\xcf\x7d\xa5\x9c\xc2\xb3\xd9\xd0\x69\x2d\xd2\xa2\
\x0b\xa3\x86\x34\x80\xe2\x5b\x1b\x85\xee\x86\x0c\x62\xbf\x51\x36\
\x00\x00\x00\x05\x00\x00\x00\x04\xd2\xf1\x4f\xf6\x34\x6a\xf9\x64\
\x56\x9f\x7d\x6c\xb8\x80\xa1\xb6\x6c\x50\x04\x91\x7d\xa6\xea\xfe\
\x4d\x9e\xf6\xc6\x40\x7b\x3d\xb0\xe5\x48\x5b\x12\x2d\x9e\xbe\x15\
\xcd\xa9\x3c\xfe\xc5\x82\xd7\xab\x00\x00\x00\x0a\x00\x00\x00\x04\
\x07\x03\xc4\x91\xe7\x55\x8b\x35\x01\x1e\xce\x35\x92\xea\xa5\xda\
\x4d\x91\x87\x86\x77\x12\x33\xe8\x35\x3b\xc4\xf6\x23\x23\x18\x5c\
\x95\xca\xe0\x5b\x89\x9e\x35\xdf\xfd\x71\x70\x54\x70\x62\x09\x98\
\x8e\xbf\xdf\x6e\x37\x96\x0b\xb5\xc3\x8d\x76\x57\xe8\xbf\xfe\xef\
\x9b\xc0\x42\xda\x4b\x45\x25\x65\x04\x85\xc6\x6d\x0c\xe1\x9b\x31\
\x75\x87\xc6\xba\x4b\xff\xcc\x42\x8e\x25\xd0\x89\x31\xe7\x2d\xfb\
\x6a\x12\x0c\x56\x12\x34\x42\x58\xb8\x5e\xfd\xb7\xdb\x1d\xb9\xe1\
\x86\x5a\x73\xca\xf9\x65\x57\xeb\x39\xed\x3e\x3f\x42\x69\x33\xac\
\x9e\xed\xdb\x03\xa1\xd2\x37\x4a\xf7\xbf\x77\x18\x55\x77\x45\x62\
\x37\xf9\xde\x2d\x60\x11\x3c\x23\xf8\x46\xdf\x26\xfa\x94\x20\x08\
\xa6\x98\x99\x4c\x08\x27\xd9\x0e\x86\xd4\x3e\x0d\xf7\xf4\xbf\xcd\
\xb0\x9b\x86\xa3\x73\xb9\x82\x88\xb7\x09\x4a\xd8\x1a\x01\x85\xac\
\x10\x0e\x4f\x2c\x5f\xc3\x8c\x00\x3c\x1a\xb6\xfe\xa4\x79\xeb\x2f\
\x5e\xbe\x48\xf5\x84\xd7\x15\x9b\x8a\xda\x03\x58\x6e\x65\xad\x9c\
\x96\x9f\x6a\xec\xbf\xe4\x4c\xf3\x56\x88\x8a\x7b\x15\xa3\xff\x07\
\x4f\x77\x17\x60\xb2\x6f\x9c\x04\x88\x4e\xe1\xfa\xa3\x29\xfb\xf4\
\xe6\x1a\xf2\x3a\xee\x7f\xa5\xd4\xd9\xa5\xdf\xcf\x43\xc4\xc2\x6c\
\xe8\xae\xa2\xce\x8a\x29\x90\xd7\xba\x7b\x57\x10\x8b\x47\xda\xbf\
\xbe\xad\xb2\xb2\x5b\x3c\xac\xc1\xac\x0c\xef\x34\x6c\xbb\x90\xfb\
\x04\x4b\xee\xe4\xfa\xc2\x60\x3a\x44\x2b\xdf\x7e\x50\x72\x43\xb7\
\x31\x9c\x99\x44\xb1\x58\x6e\x89\x9d\x43\x1c\x7f\x91\xbc\xcc\xc8\
\x69\x0d\xbf\x59\xb2\x83\x86\xb2\x31\x5f\x3d\x36\xef\x2e\xaa\x3c\
\xf3\x0b\x2b\x51\xf4\x8b\x71\xb0\x03\xdf\xb0\x82\x49\x48\x42\x01\
\x04\x3f\x65\xf5\xa3\xef\x6b\xbd\x61\xdd\xfe\xe8\x1a\xca\x9c\xe6\
\x00\x81\x26\x2a\x00\x00\x04\x80\xdc\xbc\x9a\x3d\xa6\xfb\xef\x5c\
\x1c\x0a\x55\xe4\x8a\x0e\x72\x9f\x91\x84\xfc\xb1\x40\x7c\x31\x52\
\x9d\xb2\x68\xf6\xfe\x50\x03\x2a\x36\x3c\x98\x01\x30\x68\x37\xfa\
\xfa\xbd\xf9\x57\xfd\x97\xea\xfc\x80\xdb\xd1\x65\xe4\x35\xd0\xe2\
\xdf\xd8\x36\xa2\x8b\x35\x40\x23\x92\x4b\x6f\xb7\xe4\x8b\xc0\xb3\
\xed\x95\xee\xa6\x4c\x2d\x40\x2f\x4d\x73\x4c\x8d\xc2\x6f\x3a\xc5\
\x91\x82\x5d\xae\xf0\x1e\xae\x3c\x38\xe3\x32\x8d\x00\xa7\x7d\xc6\
\x57\x03\x4f\x28\x7c\xcb\x0f\x0e\x1c\x9a\x7c\xbd\xc8\x28\xf6\x27\
\x20\x5e\x47\x37\xb8\x4b\x58\x37\x65\x51\xd4\x4c\x12\xc3\xc2\x15\
\xc8\x12\xa0\x97\x07\x89\xc8\x3d\xe5\x1d\x6a\xd7\x87\x27\x19\x63\
\x32\x7f\x0a\x5f\xbb\x6b\x59\x07\xde\xc0\x2c\x9a\x90\x93\x4a\xf5\
\xa1\xc6\x3b\x72\xc8\x26\x53\x60\x5d\x1d\xcc\xe5\x15\x96\xb3\xc2\
\xb4\x56\x96\x68\x9f\x2e\xb3\x82\x00\x74\x97\x55\x76\x92\xca\xac\
\x4d\x57\xb5\xde\x9f\x55\x69\xbc\x2a\xd0\x13\x7f\xd4\x7f\xb4\x7e\
\x66\x4f\xcb\x6d\xb4\x97\x1f\x5b\x3e\x07\xac\xed\xa9\xac\x13\x0e\
\x9f\x38\x18\x2d\xe9\x94\xcf\xf1\x92\xec\x0e\x82\xfd\x6d\x4c\xb7\
\xf3\xfe\x00\x81\x25\x89\xb7\xa7\xce\x51\x54\x40\x45\x64\x33\x01\
\x6b\x84\xa5\x9b\xec\x66\x19\xa1\xc6\xc0\xb3\x7d\xd1\x45\x0e\xd4\
\xf2\xd8\xb5\x84\x41\x0c\xed\xa8\x02\x5f\x5d\x2d\x8d\xd0\xd2\x17\
\x6f\xc1\xcf\x2c\xc0\x6f\xa8\xc8\x2b\xed\x4d\x94\x4e\x71\x33\x9e\
\xce\x78\x0f\xd0\x25\xbd\x41\xec\x34\xeb\xff\x9d\x42\x70\xa3\x22\
\x4e\x01\x9f\xcb\x44\x44\x74\xd4\x82\xfd\x2d\xbe\x75\xef\xb2\x03\
\x89\xcc\x10\xcd\x60\x0a\xbb\x54\xc4\x7e\xde\x93\xe0\x8c\x11\x4e\
\xdb\x04\x11\x7d\x71\x4d\xc1\xd5\x25\xe1\x1b\xed\x87\x56\x19\x2f\
\x92\x9d\x15\x46\x2b\x93\x9f\xf3\xf5\x2f\x22\x52\xda\x2e\xd6\x4d\
\x8f\xae\x88\x81\x8b\x1e\xfa\x2c\x7b\x08\xc8\x79\x4f\xb1\xb2\x14\
\xaa\x23\x3d\xb3\x16\x28\x33\x14\x1e\xa4\x38\x3f\x1a\x6f\x12\x0b\
\xe1\xdb\x82\xce\x36\x30\xb3\x42\x91\x14\x46\x31\x57\xa6\x4e\x91\
\x23\x4d\x47\x5e\x2f\x79\xcb\xf0\x5e\x4d\xb6\xa9\x40\x7d\x72\xc6\
\xbf\xf7\xd1\x19\x8b\x5c\x4d\x6a\xad\x28\x31\xdb\x61\x27\x49\x93\
\x71\x5a\x01\x82\xc7\xdc\x80\x89\xe3\x2c\x85\x31\xde\xed\x4f\x74\
\x31\xc0\x7c\x02\x19\x5e\xba\x2e\xf9\x1e\xfb\x56\x13\xc3\x7a\xf7\
\xae\x0c\x06\x6b\xab\xc6\x93\x69\x70\x0e\x1d\xd2\x6e\xdd\xc0\xd2\
\x16\xc7\x81\xd5\x6e\x4c\xe4\x7e\x33\x03\xfa\x73\x00\x7f\xf7\xb9\
\x49\xef\x23\xbe\x2a\xa4\xdb\xf2\x52\x06\xfe\x45\xc2\x0d\xd8\x88\
\x39\x5b\x25\x26\x39\x1a\x72\x49\x96\xa4\x41\x56\xbe\xac\x80\x82\
\x12\x85\x87\x92\xbf\x8e\x74\xcb\xa4\x9d\xee\x5e\x88\x12\xe0\x19\
\xda\x87\x45\x4b\xff\x9e\x84\x7e\xd8\x3d\xb0\x7a\xf3\x13\x74\x30\
\x82\xf8\x80\xa2\x78\xf6\x82\xc2\xbd\x0a\xd6\x88\x7c\xb5\x9f\x65\
\x2e\x15\x59\x87\xd6\x1b\xbf\x6a\x88\xd3\x6e\xe9\x3b\x60\x72\xe6\
\x65\x6d\x9c\xcb\xaa\xe3\xd6\x55\x85\x2e\x38\xde\xb3\xa2\xdc\xf8\
\x05\x8d\xc9\xfb\x6f\x2a\xb3\xd3\xb3\x53\x9e\xb7\x7b\x24\x8a\x66\
\x10\x91\xd0\x5e\xb6\xe2\xf2\x97\x77\x4f\xe6\x05\x35\x98\x45\x7c\
\xc6\x19\x08\x31\x8d\xe4\xb8\x26\xf0\xfc\x86\xd4\xbb\x11\x7d\x33\
\xe8\x65\xaa\x80\x50\x09\xcc\x29\x18\xd9\xc2\xf8\x40\xc4\xda\x43\
\xa7\x03\xad\x9f\x5b\x58\x06\x16\x3d\x71\x61\x69\x6b\x5a\x0a\xdc\
\x00\x00\x00\x05\xd5\xc0\xd1\xbe\xbb\x06\x04\x8e\xd6\xfe\x2e\xf2\
\xc6\xce\xf3\x05\xb3\xed\x63\x39\x41\xeb\xc8\xb3\xbe\xc9\x73\x87\
\x54\xcd\xdd\x60\xe1\x92\x0a\xda\x52\xf4\x3d\x05\x5b\x50\x31\xce\
\xe6\x19\x25\x20\xd6\xa5\x11\x55\x14\x85\x1c\xe7\xfd\x44\x8d\x4a\
\x39\xfa\xe2\xab\x23\x35\xb5\x25\xf4\x84\xe9\xb4\x0d\x6a\x4a\x96\
\x93\x94\x84\x3b\xdc\xf6\xd1\x4c\x48\xe8\x01\x5e\x08\xab\x92\x66\
\x2c\x05\xc6\xe9\xf9\x0b\x65\xa7\xa6\x20\x16\x89\x99\x9f\x32\xbf\
\xd3\x68\xe5\xe3\xec\x9c\xb7\x0a\xc7\xb8\x39\x90\x03\xf1\x75\xc4\
\x08\x85\x08\x1a\x09\xab\x30\x34\x91\x1f\xe1\x25\x63\x10\x51\xdf\
\x04\x08\xb3\x94\x6b\x0b\xde\x79\x09\x11\xe8\x97\x8b\xa0\x7d\xd5\
\x6c\x73\xe7\xee\
'''

# draft-mcgrew Test Case 2
hashsig_tc2_key = b'''\
\x30\x53\x30\x0f\x06\x0b\x2a\x86\x48\x86\xf7\x0d\x01\x09\x10\x03\
\x11\x05\x00\x03\x40\x00\x30\x3d\x02\x01\x02\x02\x01\x06\x02\x01\
\x03\x04\x10\xd0\x8f\xab\xd4\xa2\x09\x1f\xf0\xa8\xcb\x4e\xd8\x34\
\xe7\x45\x34\x04\x20\x32\xa5\x88\x85\xcd\x9b\xa0\x43\x12\x35\x46\
\x6b\xff\x96\x51\xc6\xc9\x21\x24\x40\x4d\x45\xfa\x53\xcf\x16\x1c\
\x28\xf1\xad\x5a\x8e\
'''
hashsig_tc2_msg = b'''\
\x54\x68\x65\x20\x65\x6e\x75\x6d\x65\x72\x61\x74\x69\x6f\x6e\x20\
\x69\x6e\x20\x74\x68\x65\x20\x43\x6f\x6e\x73\x74\x69\x74\x75\x74\
\x69\x6f\x6e\x2c\x20\x6f\x66\x20\x63\x65\x72\x74\x61\x69\x6e\x20\
\x72\x69\x67\x68\x74\x73\x2c\x20\x73\x68\x61\x6c\x6c\x20\x6e\x6f\
\x74\x20\x62\x65\x20\x63\x6f\x6e\x73\x74\x72\x75\x65\x64\x20\x74\
\x6f\x20\x64\x65\x6e\x79\x20\x6f\x72\x20\x64\x69\x73\x70\x61\x72\
\x61\x67\x65\x20\x6f\x74\x68\x65\x72\x73\x20\x72\x65\x74\x61\x69\
\x6e\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x70\x65\x6f\x70\x6c\
\x65\x2e\x0a\
'''
hashsig_tc2_sig = b'''\
\x00\x00\x00\x01\x00\x00\x00\x03\x00\x00\x00\x03\x3d\x46\xbe\xe8\
\x66\x0f\x8f\x21\x5d\x3f\x96\x40\x8a\x7a\x64\xcf\x1c\x4d\xa0\x2b\
\x63\xa5\x5f\x62\xc6\x66\xef\x57\x07\xa9\x14\xce\x06\x74\xe8\xcb\
\x7a\x55\xf0\xc4\x8d\x48\x4f\x31\xf3\xaa\x4a\xf9\x71\x9a\x74\xf2\
\x2c\xf8\x23\xb9\x44\x31\xd0\x1c\x92\x6e\x2a\x76\xbb\x71\x22\x6d\
\x27\x97\x00\xec\x81\xc9\xe9\x5f\xb1\x1a\x0d\x10\xd0\x65\x27\x9a\
\x57\x96\xe2\x65\xae\x17\x73\x7c\x44\xeb\x8c\x59\x45\x08\xe1\x26\
\xa9\xa7\x87\x0b\xf4\x36\x08\x20\xbd\xeb\x9a\x01\xd9\x69\x37\x79\
\xe4\x16\x82\x8e\x75\xbd\xdd\x7d\x8c\x70\xd5\x0a\x0a\xc8\xba\x39\
\x81\x09\x09\xd4\x45\xf4\x4c\xb5\xbb\x58\xde\x73\x7e\x60\xcb\x43\
\x45\x30\x27\x86\xef\x2c\x6b\x14\xaf\x21\x2c\xa1\x9e\xde\xaa\x3b\
\xfc\xfe\x8b\xaa\x66\x21\xce\x88\x48\x0d\xf2\x37\x1d\xd3\x7a\xdd\
\x73\x2c\x9d\xe4\xea\x2c\xe0\xdf\xfa\x53\xc9\x26\x49\xa1\x8d\x39\
\xa5\x07\x88\xf4\x65\x29\x87\xf2\x26\xa1\xd4\x81\x68\x20\x5d\xf6\
\xae\x7c\x58\xe0\x49\xa2\x5d\x49\x07\xed\xc1\xaa\x90\xda\x8a\xa5\
\xe5\xf7\x67\x17\x73\xe9\x41\xd8\x05\x53\x60\x21\x5c\x6b\x60\xdd\
\x35\x46\x3c\xf2\x24\x0a\x9c\x06\xd6\x94\xe9\xcb\x54\xe7\xb1\xe1\
\xbf\x49\x4d\x0d\x1a\x28\xc0\xd3\x1a\xcc\x75\x16\x1f\x4f\x48\x5d\
\xfd\x3c\xb9\x57\x8e\x83\x6e\xc2\xdc\x72\x2f\x37\xed\x30\x87\x2e\
\x07\xf2\xb8\xbd\x03\x74\xeb\x57\xd2\x2c\x61\x4e\x09\x15\x0f\x6c\
\x0d\x87\x74\xa3\x9a\x6e\x16\x82\x11\x03\x5d\xc5\x29\x88\xab\x46\
\xea\xca\x9e\xc5\x97\xfb\x18\xb4\x93\x6e\x66\xef\x2f\x0d\xf2\x6e\
\x8d\x1e\x34\xda\x28\xcb\xb3\xaf\x75\x23\x13\x72\x0c\x7b\x34\x54\
\x34\xf7\x2d\x65\x31\x43\x28\xbb\xb0\x30\xd0\xf0\xf6\xd5\xe4\x7b\
\x28\xea\x91\x00\x8f\xb1\x1b\x05\x01\x77\x05\xa8\xbe\x3b\x2a\xdb\
\x83\xc6\x0a\x54\xf9\xd1\xd1\xb2\xf4\x76\xf9\xe3\x93\xeb\x56\x95\
\x20\x3d\x2b\xa6\xad\x81\x5e\x6a\x11\x1e\xa2\x93\xdc\xc2\x10\x33\
\xf9\x45\x3d\x49\xc8\xe5\xa6\x38\x7f\x58\x8b\x1e\xa4\xf7\x06\x21\
\x7c\x15\x1e\x05\xf5\x5a\x6e\xb7\x99\x7b\xe0\x9d\x56\xa3\x26\xa3\
\x2f\x9c\xba\x1f\xbe\x1c\x07\xbb\x49\xfa\x04\xce\xcf\x9d\xf1\xa1\
\xb8\x15\x48\x3c\x75\xd7\xa2\x7c\xc8\x8a\xd1\xb1\x23\x8e\x5e\xa9\
\x86\xb5\x3e\x08\x70\x45\x72\x3c\xe1\x61\x87\xed\xa2\x2e\x33\xb2\
\xc7\x07\x09\xe5\x32\x51\x02\x5a\xbd\xe8\x93\x96\x45\xfc\x8c\x06\
\x93\xe9\x77\x63\x92\x8f\x00\xb2\xe3\xc7\x5a\xf3\x94\x2d\x8d\xda\
\xee\x81\xb5\x9a\x6f\x1f\x67\xef\xda\x0e\xf8\x1d\x11\x87\x3b\x59\
\x13\x7f\x67\x80\x0b\x35\xe8\x1b\x01\x56\x3d\x18\x7c\x4a\x15\x75\
\xa1\xac\xb9\x2d\x08\x7b\x51\x7a\x88\x33\x38\x3f\x05\xd3\x57\xef\
\x46\x78\xde\x0c\x57\xff\x9f\x1b\x2d\xa6\x1d\xfd\xe5\xd8\x83\x18\
\xbc\xdd\xe4\xd9\x06\x1c\xc7\x5c\x2d\xe3\xcd\x47\x40\xdd\x77\x39\
\xca\x3e\xf6\x6f\x19\x30\x02\x6f\x47\xd9\xeb\xaa\x71\x3b\x07\x17\
\x6f\x76\xf9\x53\xe1\xc2\xe7\xf8\xf2\x71\xa6\xca\x37\x5d\xbf\xb8\
\x3d\x71\x9b\x16\x35\xa7\xd8\xa1\x38\x91\x95\x79\x44\xb1\xc2\x9b\
\xb1\x01\x91\x3e\x16\x6e\x11\xbd\x5f\x34\x18\x6f\xa6\xc0\xa5\x55\
\xc9\x02\x6b\x25\x6a\x68\x60\xf4\x86\x6b\xd6\xd0\xb5\xbf\x90\x62\
\x70\x86\xc6\x14\x91\x33\xf8\x28\x2c\xe6\xc9\xb3\x62\x24\x42\x44\
\x3d\x5e\xca\x95\x9d\x6c\x14\xca\x83\x89\xd1\x2c\x40\x68\xb5\x03\
\xe4\xe3\xc3\x9b\x63\x5b\xea\x24\x5d\x9d\x05\xa2\x55\x8f\x24\x9c\
\x96\x61\xc0\x42\x7d\x2e\x48\x9c\xa5\xb5\xdd\xe2\x20\xa9\x03\x33\
\xf4\x86\x2a\xec\x79\x32\x23\xc7\x81\x99\x7d\xa9\x82\x66\xc1\x2c\
\x50\xea\x28\xb2\xc4\x38\xe7\xa3\x79\xeb\x10\x6e\xca\x0c\x7f\xd6\
\x00\x6e\x9b\xf6\x12\xf3\xea\x0a\x45\x4b\xa3\xbd\xb7\x6e\x80\x27\
\x99\x2e\x60\xde\x01\xe9\x09\x4f\xdd\xeb\x33\x49\x88\x39\x14\xfb\
\x17\xa9\x62\x1a\xb9\x29\xd9\x70\xd1\x01\xe4\x5f\x82\x78\xc1\x4b\
\x03\x2b\xca\xb0\x2b\xd1\x56\x92\xd2\x1b\x6c\x5c\x20\x4a\xbb\xf0\
\x77\xd4\x65\x55\x3b\xd6\xed\xa6\x45\xe6\xc3\x06\x5d\x33\xb1\x0d\
\x51\x8a\x61\xe1\x5e\xd0\xf0\x92\xc3\x22\x26\x28\x1a\x29\xc8\xa0\
\xf5\x0c\xde\x0a\x8c\x66\x23\x6e\x29\xc2\xf3\x10\xa3\x75\xce\xbd\
\xa1\xdc\x6b\xb9\xa1\xa0\x1d\xae\x6c\x7a\xba\x8e\xbe\xdc\x63\x71\
\xa7\xd5\x2a\xac\xb9\x55\xf8\x3b\xd6\xe4\xf8\x4d\x29\x49\xdc\xc1\
\x98\xfb\x77\xc7\xe5\xcd\xf6\x04\x0b\x0f\x84\xfa\xf8\x28\x08\xbf\
\x98\x55\x77\xf0\xa2\xac\xf2\xec\x7e\xd7\xc0\xb0\xae\x8a\x27\x0e\
\x95\x17\x43\xff\x23\xe0\xb2\xdd\x12\xe9\xc3\xc8\x28\xfb\x55\x98\
\xa2\x24\x61\xaf\x94\xd5\x68\xf2\x92\x40\xba\x28\x20\xc4\x59\x1f\
\x71\xc0\x88\xf9\x6e\x09\x5d\xd9\x8b\xea\xe4\x56\x57\x9e\xbb\xba\
\x36\xf6\xd9\xca\x26\x13\xd1\xc2\x6e\xee\x4d\x8c\x73\x21\x7a\xc5\
\x96\x2b\x5f\x31\x47\xb4\x92\xe8\x83\x15\x97\xfd\x89\xb6\x4a\xa7\
\xfd\xe8\x2e\x19\x74\xd2\xf6\x77\x95\x04\xdc\x21\x43\x5e\xb3\x10\
\x93\x50\x75\x6b\x9f\xda\xbe\x1c\x6f\x36\x80\x81\xbd\x40\xb2\x7e\
\xbc\xb9\x81\x9a\x75\xd7\xdf\x8b\xb0\x7b\xb0\x5d\xb1\xba\xb7\x05\
\xa4\xb7\xe3\x71\x25\x18\x63\x39\x46\x4a\xd8\xfa\xaa\x4f\x05\x2c\
\xc1\x27\x29\x19\xfd\xe3\xe0\x25\xbb\x64\xaa\x8e\x0e\xb1\xfc\xbf\
\xcc\x25\xac\xb5\xf7\x18\xce\x4f\x7c\x21\x82\xfb\x39\x3a\x18\x14\
\xb0\xe9\x42\x49\x0e\x52\xd3\xbc\xa8\x17\xb2\xb2\x6e\x90\xd4\xc9\
\xb0\xcc\x38\x60\x8a\x6c\xef\x5e\xb1\x53\xaf\x08\x58\xac\xc8\x67\
\xc9\x92\x2a\xed\x43\xbb\x67\xd7\xb3\x3a\xcc\x51\x93\x13\xd2\x8d\
\x41\xa5\xc6\xfe\x6c\xf3\x59\x5d\xd5\xee\x63\xf0\xa4\xc4\x06\x5a\
\x08\x35\x90\xb2\x75\x78\x8b\xee\x7a\xd8\x75\xa7\xf8\x8d\xd7\x37\
\x20\x70\x8c\x6c\x6c\x0e\xcf\x1f\x43\xbb\xaa\xda\xe6\xf2\x08\x55\
\x7f\xdc\x07\xbd\x4e\xd9\x1f\x88\xce\x4c\x0d\xe8\x42\x76\x1c\x70\
\xc1\x86\xbf\xda\xfa\xfc\x44\x48\x34\xbd\x34\x18\xbe\x42\x53\xa7\
\x1e\xaf\x41\xd7\x18\x75\x3a\xd0\x77\x54\xca\x3e\xff\xd5\x96\x0b\
\x03\x36\x98\x17\x95\x72\x14\x26\x80\x35\x99\xed\x5b\x2b\x75\x16\
\x92\x0e\xfc\xbe\x32\xad\xa4\xbc\xf6\xc7\x3b\xd2\x9e\x3f\xa1\x52\
\xd9\xad\xec\xa3\x60\x20\xfd\xee\xee\x1b\x73\x95\x21\xd3\xea\x8c\
\x0d\xa4\x97\x00\x3d\xf1\x51\x38\x97\xb0\xf5\x47\x94\xa8\x73\x67\
\x0b\x8d\x93\xbc\xca\x2a\xe4\x7e\x64\x42\x4b\x74\x23\xe1\xf0\x78\
\xd9\x55\x4b\xb5\x23\x2c\xc6\xde\x8a\xae\x9b\x83\xfa\x5b\x95\x10\
\xbe\xb3\x9c\xcf\x4b\x4e\x1d\x9c\x0f\x19\xd5\xe1\x7f\x58\xe5\xb8\
\x70\x5d\x9a\x68\x37\xa7\xd9\xbf\x99\xcd\x13\x38\x7a\xf2\x56\xa8\
\x49\x16\x71\xf1\xf2\xf2\x2a\xf2\x53\xbc\xff\x54\xb6\x73\x19\x9b\
\xdb\x7d\x05\xd8\x10\x64\xef\x05\xf8\x0f\x01\x53\xd0\xbe\x79\x19\
\x68\x4b\x23\xda\x8d\x42\xff\x3e\xff\xdb\x7c\xa0\x98\x50\x33\xf3\
\x89\x18\x1f\x47\x65\x91\x38\x00\x3d\x71\x2b\x5e\xc0\xa6\x14\xd3\
\x1c\xc7\x48\x7f\x52\xde\x86\x64\x91\x6a\xf7\x9c\x98\x45\x6b\x2c\
\x94\xa8\x03\x80\x83\xdb\x55\x39\x1e\x34\x75\x86\x22\x50\x27\x4a\
\x1d\xe2\x58\x4f\xec\x97\x5f\xb0\x95\x36\x79\x2c\xfb\xfc\xf6\x19\
\x28\x56\xcc\x76\xeb\x5b\x13\xdc\x47\x09\xe2\xf7\x30\x1d\xdf\xf2\
\x6e\xc1\xb2\x3d\xe2\xd1\x88\xc9\x99\x16\x6c\x74\xe1\xe1\x4b\xbc\
\x15\xf4\x57\xcf\x4e\x47\x1a\xe1\x3d\xcb\xdd\x9c\x50\xf4\xd6\x46\
\xfc\x62\x78\xe8\xfe\x7e\xb6\xcb\x5c\x94\x10\x0f\xa8\x70\x18\x73\
\x80\xb7\x77\xed\x19\xd7\x86\x8f\xd8\xca\x7c\xeb\x7f\xa7\xd5\xcc\
\x86\x1c\x5b\xda\xc9\x8e\x74\x95\xeb\x0a\x2c\xee\xc1\x92\x4a\xe9\
\x79\xf4\x4c\x53\x90\xeb\xed\xdd\xc6\x5d\x6e\xc1\x12\x87\xd9\x78\
\xb8\xdf\x06\x42\x19\xbc\x56\x79\xf7\xd7\xb2\x64\xa7\x6f\xf2\x72\
\xb2\xac\x9f\x2f\x7c\xfc\x9f\xdc\xfb\x6a\x51\x42\x82\x40\x02\x7a\
\xfd\x9d\x52\xa7\x9b\x64\x7c\x90\xc2\x70\x9e\x06\x0e\xd7\x0f\x87\
\x29\x9d\xd7\x98\xd6\x8f\x4f\xad\xd3\xda\x6c\x51\xd8\x39\xf8\x51\
\xf9\x8f\x67\x84\x0b\x96\x4e\xbe\x73\xf8\xce\xc4\x15\x72\x53\x8e\
\xc6\xbc\x13\x10\x34\xca\x28\x94\xeb\x73\x6b\x3b\xda\x93\xd9\xf5\
\xf6\xfa\x6f\x6c\x0f\x03\xce\x43\x36\x2b\x84\x14\x94\x03\x55\xfb\
\x54\xd3\xdf\xdd\x03\x63\x3a\xe1\x08\xf3\xde\x3e\xbc\x85\xa3\xff\
\x51\xef\xee\xa3\xbc\x2c\xf2\x7e\x16\x58\xf1\x78\x9e\xe6\x12\xc8\
\x3d\x0f\x5f\xd5\x6f\x7c\xd0\x71\x93\x0e\x29\x46\xbe\xee\xca\xa0\
\x4d\xcc\xea\x9f\x97\x78\x60\x01\x47\x5e\x02\x94\xbc\x28\x52\xf6\
\x2e\xb5\xd3\x9b\xb9\xfb\xee\xf7\x59\x16\xef\xe4\x4a\x66\x2e\xca\
\xe3\x7e\xde\x27\xe9\xd6\xea\xdf\xde\xb8\xf8\xb2\xb2\xdb\xcc\xbf\
\x96\xfa\x6d\xba\xf7\x32\x1f\xb0\xe7\x01\xf4\xd4\x29\xc2\xf4\xdc\
\xd1\x53\xa2\x74\x25\x74\x12\x6e\x5e\xac\xcc\x77\x68\x6a\xcf\x6e\
\x3e\xe4\x8f\x42\x37\x66\xe0\xfc\x46\x68\x10\xa9\x05\xff\x54\x53\
\xec\x99\x89\x7b\x56\xbc\x55\xdd\x49\xb9\x91\x14\x2f\x65\x04\x3f\
\x2d\x74\x4e\xeb\x93\x5b\xa7\xf4\xef\x23\xcf\x80\xcc\x5a\x8a\x33\
\x5d\x36\x19\xd7\x81\xe7\x45\x48\x26\xdf\x72\x0e\xec\x82\xe0\x60\
\x34\xc4\x46\x99\xb5\xf0\xc4\x4a\x87\x87\x75\x2e\x05\x7f\xa3\x41\
\x9b\x5b\xb0\xe2\x5d\x30\x98\x1e\x41\xcb\x13\x61\x32\x2d\xba\x8f\
\x69\x93\x1c\xf4\x2f\xad\x3f\x3b\xce\x6d\xed\x5b\x8b\xfc\x3d\x20\
\xa2\x14\x88\x61\xb2\xaf\xc1\x45\x62\xdd\xd2\x7f\x12\x89\x7a\xbf\
\x06\x85\x28\x8d\xcc\x5c\x49\x82\xf8\x26\x02\x68\x46\xa2\x4b\xf7\
\x7e\x38\x3c\x7a\xac\xab\x1a\xb6\x92\xb2\x9e\xd8\xc0\x18\xa6\x5f\
\x3d\xc2\xb8\x7f\xf6\x19\xa6\x33\xc4\x1b\x4f\xad\xb1\xc7\x87\x25\
\xc1\xf8\xf9\x22\xf6\x00\x97\x87\xb1\x96\x42\x47\xdf\x01\x36\xb1\
\xbc\x61\x4a\xb5\x75\xc5\x9a\x16\xd0\x89\x91\x7b\xd4\xa8\xb6\xf0\
\x4d\x95\xc5\x81\x27\x9a\x13\x9b\xe0\x9f\xcf\x6e\x98\xa4\x70\xa0\
\xbc\xec\xa1\x91\xfc\xe4\x76\xf9\x37\x00\x21\xcb\xc0\x55\x18\xa7\
\xef\xd3\x5d\x89\xd8\x57\x7c\x99\x0a\x5e\x19\x96\x1b\xa1\x62\x03\
\xc9\x59\xc9\x18\x29\xba\x74\x97\xcf\xfc\xbb\x4b\x29\x45\x46\x45\
\x4f\xa5\x38\x8a\x23\xa2\x2e\x80\x5a\x5c\xa3\x5f\x95\x65\x98\x84\
\x8b\xda\x67\x86\x15\xfe\xc2\x8a\xfd\x5d\xa6\x1a\x00\x00\x00\x06\
\xb3\x26\x49\x33\x13\x05\x3c\xed\x38\x76\xdb\x9d\x23\x71\x48\x18\
\x1b\x71\x73\xbc\x7d\x04\x2c\xef\xb4\xdb\xe9\x4d\x2e\x58\xcd\x21\
\xa7\x69\xdb\x46\x57\xa1\x03\x27\x9b\xa8\xef\x3a\x62\x9c\xa8\x4e\
\xe8\x36\x17\x2a\x9c\x50\xe5\x1f\x45\x58\x17\x41\xcf\x80\x83\x15\
\x0b\x49\x1c\xb4\xec\xbb\xab\xec\x12\x8e\x7c\x81\xa4\x6e\x62\xa6\
\x7b\x57\x64\x0a\x0a\x78\xbe\x1c\xbf\x7d\xd9\xd4\x19\xa1\x0c\xd8\
\x68\x6d\x16\x62\x1a\x80\x81\x6b\xfd\xb5\xbd\xc5\x62\x11\xd7\x2c\
\xa7\x0b\x81\xf1\x11\x7d\x12\x95\x29\xa7\x57\x0c\xf7\x9c\xf5\x2a\
\x70\x28\xa4\x85\x38\xec\xdd\x3b\x38\xd3\xd5\xd6\x2d\x26\x24\x65\
\x95\xc4\xfb\x73\xa5\x25\xa5\xed\x2c\x30\x52\x4e\xbb\x1d\x8c\xc8\
\x2e\x0c\x19\xbc\x49\x77\xc6\x89\x8f\xf9\x5f\xd3\xd3\x10\xb0\xba\
\xe7\x16\x96\xce\xf9\x3c\x6a\x55\x24\x56\xbf\x96\xe9\xd0\x75\xe3\
\x83\xbb\x75\x43\xc6\x75\x84\x2b\xaf\xbf\xc7\xcd\xb8\x84\x83\xb3\
\x27\x6c\x29\xd4\xf0\xa3\x41\xc2\xd4\x06\xe4\x0d\x46\x53\xb7\xe4\
\xd0\x45\x85\x1a\xcf\x6a\x0a\x0e\xa9\xc7\x10\xb8\x05\xcc\xed\x46\
\x35\xee\x8c\x10\x73\x62\xf0\xfc\x8d\x80\xc1\x4d\x0a\xc4\x9c\x51\
\x67\x03\xd2\x6d\x14\x75\x2f\x34\xc1\xc0\xd2\xc4\x24\x75\x81\xc1\
\x8c\x2c\xf4\xde\x48\xe9\xce\x94\x9b\xe7\xc8\x88\xe9\xca\xeb\xe4\
\xa4\x15\xe2\x91\xfd\x10\x7d\x21\xdc\x1f\x08\x4b\x11\x58\x20\x82\
\x49\xf2\x8f\x4f\x7c\x7e\x93\x1b\xa7\xb3\xbd\x0d\x82\x4a\x45\x70\
\x00\x00\x00\x05\x00\x00\x00\x04\x21\x5f\x83\xb7\xcc\xb9\xac\xbc\
\xd0\x8d\xb9\x7b\x0d\x04\xdc\x2b\xa1\xcd\x03\x58\x33\xe0\xe9\x00\
\x59\x60\x3f\x26\xe0\x7a\xd2\xaa\xd1\x52\x33\x8e\x7a\x5e\x59\x84\
\xbc\xd5\xf7\xbb\x4e\xba\x40\xb7\x00\x00\x00\x04\x00\x00\x00\x04\
\x0e\xb1\xed\x54\xa2\x46\x0d\x51\x23\x88\xca\xd5\x33\x13\x8d\x24\
\x05\x34\xe9\x7b\x1e\x82\xd3\x3b\xd9\x27\xd2\x01\xdf\xc2\x4e\xbb\
\x11\xb3\x64\x90\x23\x69\x6f\x85\x15\x0b\x18\x9e\x50\xc0\x0e\x98\
\x85\x0a\xc3\x43\xa7\x7b\x36\x38\x31\x9c\x34\x7d\x73\x10\x26\x9d\
\x3b\x77\x14\xfa\x40\x6b\x8c\x35\xb0\x21\xd5\x4d\x4f\xda\xda\x7b\
\x9c\xe5\xd4\xba\x5b\x06\x71\x9e\x72\xaa\xf5\x8c\x5a\xae\x7a\xca\
\x05\x7a\xa0\xe2\xe7\x4e\x7d\xcf\xd1\x7a\x08\x23\x42\x9d\xb6\x29\
\x65\xb7\xd5\x63\xc5\x7b\x4c\xec\x94\x2c\xc8\x65\xe2\x9c\x1d\xad\
\x83\xca\xc8\xb4\xd6\x1a\xac\xc4\x57\xf3\x36\xe6\xa1\x0b\x66\x32\
\x3f\x58\x87\xbf\x35\x23\xdf\xca\xde\xe1\x58\x50\x3b\xfa\xa8\x9d\
\xc6\xbf\x59\xda\xa8\x2a\xfd\x2b\x5e\xbb\x2a\x9c\xa6\x57\x2a\x60\
\x67\xce\xe7\xc3\x27\xe9\x03\x9b\x3b\x6e\xa6\xa1\xed\xc7\xfd\xc3\
\xdf\x92\x7a\xad\xe1\x0c\x1c\x9f\x2d\x5f\xf4\x46\x45\x0d\x2a\x39\
\x98\xd0\xf9\xf6\x20\x2b\x5e\x07\xc3\xf9\x7d\x24\x58\xc6\x9d\x3c\
\x81\x90\x64\x39\x78\xd7\xa7\xf4\xd6\x4e\x97\xe3\xf1\xc4\xa0\x8a\
\x7c\x5b\xc0\x3f\xd5\x56\x82\xc0\x17\xe2\x90\x7e\xab\x07\xe5\xbb\
\x2f\x19\x01\x43\x47\x5a\x60\x43\xd5\xe6\xd5\x26\x34\x71\xf4\xee\
\xcf\x6e\x25\x75\xfb\xc6\xff\x37\xed\xfa\x24\x9d\x6c\xda\x1a\x09\
\xf7\x97\xfd\x5a\x3c\xd5\x3a\x06\x67\x00\xf4\x58\x63\xf0\x4b\x6c\
\x8a\x58\xcf\xd3\x41\x24\x1e\x00\x2d\x0d\x2c\x02\x17\x47\x2b\xf1\
\x8b\x63\x6a\xe5\x47\xc1\x77\x13\x68\xd9\xf3\x17\x83\x5c\x9b\x0e\
\xf4\x30\xb3\xdf\x40\x34\xf6\xaf\x00\xd0\xda\x44\xf4\xaf\x78\x00\
\xbc\x7a\x5c\xf8\xa5\xab\xdb\x12\xdc\x71\x8b\x55\x9b\x74\xca\xb9\
\x09\x0e\x33\xcc\x58\xa9\x55\x30\x09\x81\xc4\x20\xc4\xda\x8f\xfd\
\x67\xdf\x54\x08\x90\xa0\x62\xfe\x40\xdb\xa8\xb2\xc1\xc5\x48\xce\
\xd2\x24\x73\x21\x9c\x53\x49\x11\xd4\x8c\xca\xab\xfb\x71\xbc\x71\
\x86\x2f\x4a\x24\xeb\xd3\x76\xd2\x88\xfd\x4e\x6f\xb0\x6e\xd8\x70\
\x57\x87\xc5\xfe\xdc\x81\x3c\xd2\x69\x7e\x5b\x1a\xac\x1c\xed\x45\
\x76\x7b\x14\xce\x88\x40\x9e\xae\xbb\x60\x1a\x93\x55\x9a\xae\x89\
\x3e\x14\x3d\x1c\x39\x5b\xc3\x26\xda\x82\x1d\x79\xa9\xed\x41\xdc\
\xfb\xe5\x49\x14\x7f\x71\xc0\x92\xf4\xf3\xac\x52\x2b\x5c\xc5\x72\
\x90\x70\x66\x50\x48\x7b\xae\x9b\xb5\x67\x1e\xcc\x9c\xcc\x2c\xe5\
\x1e\xad\x87\xac\x01\x98\x52\x68\x52\x12\x22\xfb\x90\x57\xdf\x7e\
\xd4\x18\x10\xb5\xef\x0d\x4f\x7c\xc6\x73\x68\xc9\x0f\x57\x3b\x1a\
\xc2\xce\x95\x6c\x36\x5e\xd3\x8e\x89\x3c\xe7\xb2\xfa\xe1\x5d\x36\
\x85\xa3\xdf\x2f\xa3\xd4\xcc\x09\x8f\xa5\x7d\xd6\x0d\x2c\x97\x54\
\xa8\xad\xe9\x80\xad\x0f\x93\xf6\x78\x70\x75\xc3\xf6\x80\xa2\xba\
\x19\x36\xa8\xc6\x1d\x1a\xf5\x2a\xb7\xe2\x1f\x41\x6b\xe0\x9d\x2a\
\x8d\x64\xc3\xd3\xd8\x58\x29\x68\xc2\x83\x99\x02\x22\x9f\x85\xae\
\xe2\x97\xe7\x17\xc0\x94\xc8\xdf\x4a\x23\xbb\x5d\xb6\x58\xdd\x37\
\x7b\xf0\xf4\xff\x3f\xfd\x8f\xba\x5e\x38\x3a\x48\x57\x48\x02\xed\
\x54\x5b\xbe\x7a\x6b\x47\x53\x53\x33\x53\xd7\x37\x06\x06\x76\x40\
\x13\x5a\x7c\xe5\x17\x27\x9c\xd6\x83\x03\x97\x47\xd2\x18\x64\x7c\
\x86\xe0\x97\xb0\xda\xa2\x87\x2d\x54\xb8\xf3\xe5\x08\x59\x87\x62\
\x95\x47\xb8\x30\xd8\x11\x81\x61\xb6\x50\x79\xfe\x7b\xc5\x9a\x99\
\xe9\xc3\xc7\x38\x0e\x3e\x70\xb7\x13\x8f\xe5\xd9\xbe\x25\x51\x50\
\x2b\x69\x8d\x09\xae\x19\x39\x72\xf2\x7d\x40\xf3\x8d\xea\x26\x4a\
\x01\x26\xe6\x37\xd7\x4a\xe4\xc9\x2a\x62\x49\xfa\x10\x34\x36\xd3\
\xeb\x0d\x40\x29\xac\x71\x2b\xfc\x7a\x5e\xac\xbd\xd7\x51\x8d\x6d\
\x4f\xe9\x03\xa5\xae\x65\x52\x7c\xd6\x5b\xb0\xd4\xe9\x92\x5c\xa2\
\x4f\xd7\x21\x4d\xc6\x17\xc1\x50\x54\x4e\x42\x3f\x45\x0c\x99\xce\
\x51\xac\x80\x05\xd3\x3a\xcd\x74\xf1\xbe\xd3\xb1\x7b\x72\x66\xa4\
\xa3\xbb\x86\xda\x7e\xba\x80\xb1\x01\xe1\x5c\xb7\x9d\xe9\xa2\x07\
\x85\x2c\xf9\x12\x49\xef\x48\x06\x19\xff\x2a\xf8\xca\xbc\xa8\x31\
\x25\xd1\xfa\xa9\x4c\xbb\x0a\x03\xa9\x06\xf6\x83\xb3\xf4\x7a\x97\
\xc8\x71\xfd\x51\x3e\x51\x0a\x7a\x25\xf2\x83\xb1\x96\x07\x57\x78\
\x49\x61\x52\xa9\x1c\x2b\xf9\xda\x76\xeb\xe0\x89\xf4\x65\x48\x77\
\xf2\xd5\x86\xae\x71\x49\xc4\x06\xe6\x63\xea\xde\xb2\xb5\xc7\xe8\
\x24\x29\xb9\xe8\xcb\x48\x34\xc8\x34\x64\xf0\x79\x99\x53\x32\xe4\
\xb3\xc8\xf5\xa7\x2b\xb4\xb8\xc6\xf7\x4b\x0d\x45\xdc\x6c\x1f\x79\
\x95\x2c\x0b\x74\x20\xdf\x52\x5e\x37\xc1\x53\x77\xb5\xf0\x98\x43\
\x19\xc3\x99\x39\x21\xe5\xcc\xd9\x7e\x09\x75\x92\x06\x45\x30\xd3\
\x3d\xe3\xaf\xad\x57\x33\xcb\xe7\x70\x3c\x52\x96\x26\x3f\x77\x34\
\x2e\xfb\xf5\xa0\x47\x55\xb0\xb3\xc9\x97\xc4\x32\x84\x63\xe8\x4c\
\xaa\x2d\xe3\xff\xdc\xd2\x97\xba\xaa\xac\xd7\xae\x64\x6e\x44\xb5\
\xc0\xf1\x60\x44\xdf\x38\xfa\xbd\x29\x6a\x47\xb3\xa8\x38\xa9\x13\
\x98\x2f\xb2\xe3\x70\xc0\x78\xed\xb0\x42\xc8\x4d\xb3\x4c\xe3\x6b\
\x46\xcc\xb7\x64\x60\xa6\x90\xcc\x86\xc3\x02\x45\x7d\xd1\xcd\xe1\
\x97\xec\x80\x75\xe8\x2b\x39\x3d\x54\x20\x75\x13\x4e\x2a\x17\xee\
\x70\xa5\xe1\x87\x07\x5d\x03\xae\x3c\x85\x3c\xff\x60\x72\x9b\xa4\
\x00\x00\x00\x05\x4d\xe1\xf6\x96\x5b\xda\xbc\x67\x6c\x5a\x4d\xc7\
\xc3\x5f\x97\xf8\x2c\xb0\xe3\x1c\x68\xd0\x4f\x1d\xad\x96\x31\x4f\
\xf0\x9e\x6b\x3d\xe9\x6a\xee\xe3\x00\xd1\xf6\x8b\xf1\xbc\xa9\xfc\
\x58\xe4\x03\x23\x36\xcd\x81\x9a\xaf\x57\x87\x44\xe5\x0d\x13\x57\
\xa0\xe4\x28\x67\x04\xd3\x41\xaa\x0a\x33\x7b\x19\xfe\x4b\xc4\x3c\
\x2e\x79\x96\x4d\x4f\x35\x10\x89\xf2\xe0\xe4\x1c\x7c\x43\xae\x0d\
\x49\xe7\xf4\x04\xb0\xf7\x5b\xe8\x0e\xa3\xaf\x09\x8c\x97\x52\x42\
\x0a\x8a\xc0\xea\x2b\xbb\x1f\x4e\xeb\xa0\x52\x38\xae\xf0\xd8\xce\
\x63\xf0\xc6\xe5\xe4\x04\x1d\x95\x39\x8a\x6f\x7f\x3e\x0e\xe9\x7c\
\xc1\x59\x18\x49\xd4\xed\x23\x63\x38\xb1\x47\xab\xde\x9f\x51\xef\
\x9f\xd4\xe1\xc1\
'''

if __name__ == "__main__":
    main()
