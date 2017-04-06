#!/usr/bin/env python

# Test of key backup code, will evolve into unit tests and a user
# backup script after initial debugging.

#    KEY SOURCE                            KEY BACKUP
#
#                                          Generate and export KEKEK:
#                                               hal_rpc_pkey_generate_rsa()
#                                               hal_rpc_pkey_get_public_key()
#
#   Load KEKEK public   <----------------  Export KEKEK public
#
#                       {
#                               "kekek-uuid":   "[UUID]",
#                               "kekek":        "[Base64]"
#                       }
#
#       hal_rpc_pkey_load()
#       hal_rpc_pkey_export()
#
#   Export PKCS #8 and KEK   ---------->   Load PKCS #8 and KEK, import key:
#
#                       {
#                               "kekek-uuid":   "[UUID]",
#                               "pkey":         "[Base64]",
#                               "kek":          "[Base64]"
#                       }
#
#
#                                               hal_rpc_pkey_import()

from libhal import *

from Crypto.PublicKey   import RSA
from Crypto.Cipher      import AES, PKCS1_v1_5
from Crypto.Util.asn1   import DerObject, DerSequence, DerNull, DerOctetString, DerObjectId
from Crypto.Random      import new as csprng
from struct             import pack, unpack


def dumpasn1(der):
    from subprocess import call
    from tempfile import NamedTemporaryFile
    with NamedTemporaryFile() as f:
        f.write(der)
        f.flush()
        call(("dumpasn1", "-aop", f.name))

def t(x):
    return filter(x.isType, x.typeTags)[0]

hal_asn1_oid_rsaEncryption = "\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"
hal_asn1_oid_aesKeyWrap    = "\x60\x86\x48\x01\x65\x03\x04\x01\x30"

kek_length = 256/8      # We can determine this from the keywrap OID, this is for AES-256

def main():
    kekek = RSA.importKey(kekek_pem)

    from atexit import register as atexit

    hsm = HSM()
    #hsm.debug_io = args.io_log

    hsm.login(HAL_USER_WHEEL, "fnord")
    atexit(hsm.logout)

    kekek_handle = hsm.pkey_load(type  = HAL_KEY_TYPE_RSA_PUBLIC,
                                 curve = HAL_CURVE_NONE,
                                 der   = kekek.publickey().exportKey(format = "DER"))
    atexit(kekek_handle.delete)
    print "KEKEK:", kekek_handle.uuid

    pkey_handle = hsm.pkey_generate_ec(HAL_CURVE_P256, HAL_KEY_FLAG_EXPORTABLE)
    atexit(pkey_handle.delete)
    print "PKey: ", pkey_handle.uuid

    pkcs8_der, kek_der = kekek_handle.export_pkey(pkey_handle)

    pkcs8_alg, pkcs8_data = show_encrypted_pkcs8("PKCS #8:", pkcs8_der, hal_asn1_oid_aesKeyWrap)
    kek_alg,   kek_data   = show_encrypted_pkcs8("KEK:    ", kek_der,   hal_asn1_oid_rsaEncryption)

    # Voodoo to defend against Bleichenbacher Attack per Crypto.Cipher.PKCS1_v1_5 API documentation

    kek = PKCS1_v1_5.new(kekek).decrypt(kek_data, csprng().read(kek_length))

    pkey = AESKeyWrapWithPadding(kek).unwrap(pkcs8_data)

    dumpasn1(pkey)


def show_encrypted_pkcs8(label, der, oid):
    print
    print label
    dumpasn1(der)
    print
    result = parse_encrypted_pkcs8(der)
    for name, value in zip(("algorithm", "encryptedData"), result):
        print "{:14s} {}".format(name, "-".join("{:02x}".format(ord(v)) for v in value))
    print
    print "OID {}".format("matches" if result[0] == oid else "doesn't match")
    return result

def parse_encrypted_pkcs8(der):

    encryptedPrivateKeyInfo = DerSequence()
    encryptedPrivateKeyInfo.decode(der)

    encryptionAlgorithm = DerSequence()
    encryptionAlgorithm.decode(encryptedPrivateKeyInfo[0])

    algorithm = DerObjectId()
    algorithm.decode(encryptionAlgorithm[0])

    encryptedData = DerObject()
    encryptedData.decode(encryptedPrivateKeyInfo[1])

    return algorithm.payload, encryptedData.payload


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


# Static KEKEK for testing, this should come from the backup HSM.

kekek_pem = '''\
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDTtBJvz+55FBHH
0NhDZ6Xdp07kUPFxn9lYlNwg5BmSBPbXT/2JindI9NrfEx4xX0i0d3OxnbQoc8RJ
WsF2ujALBAU92yO9bjbxUbgxvecy3by/UNulLo9pOhKD2hgCkH6FWdlE7wbIfex1
pIFL1ms/h6qBme8qvXEGqTh79S5krVQG/tVZFyNyVanzrVCcAVGhZ/RqXK4Lb7pF
QJg1tNuYaQkNieiVPpoxuqAX0jP0iot2OXwlMUj2aHl/cQfdmIYKCmC3IQfuCy1m
grdW7Sb2u87tH6aFSEp4mCbScXYac7lBsi4AOQQcGR8816NslDqYU/0+cYcU4Ub/
0D8W2Nr9AgMBAAECggEBAIIJ2klUL+evrDxQzIaa5AeC/bLBBY4F4jvHNG//rLVE
11rqh5I0u5DU1pyv4ZvyK3au6SHw/PjcI3XriWqkc15Q2edk9E8npBgXWk0zmRBl
o8rgoAqWzwCT60uSa60nlI/U4OC28jO1Jcodgk5TJw2fB90T8RUPyJ2O1GNP929e
6autPcifNNBQGNAiVCMAboNHOunr0fBO28JAcEhgw5CqpjCNbWbv9YLPAaIB6Fr9
mnidOB7UNQ8Uk+bybuSz7DtsmOpbktjBcbgQVpqJyzkjsA/2LjoTavUTq2UALtk2
VeNVebfvQq7crMsfV09r0EdrAx3wawjrX/jyrbwf8AECgYEA+yfx0Fg5Kn+7ierT
nLbJ1HgIra8KabmJB629cXjhllO1gBH7NdFU/13H9dPhcehA0zYkZuvQOWWRjh28
VJhwb4fSdtlkxukqJfNNrppYhEmr3zs6RFJYb3qZKZSZE7Bo1S6WeM1cMQWY94le
GylVC5f52a6H199hHiKQ9pIjKK0CgYEA18lVm6f1L/8wC3rXB7PW628ImQoIOFaT
mAdBtfGgUfpVk8xsuipJ4bqve45l6B8s49xr3rY/j4t8wETE11h4kLaQGicRVXFq
7xJUR4xZYYnDKMC2LwSHbd0JxYekKa4uaC9Sd6g5Pyg1f8QVmXdShI0z0Hpr3aYY
hdXNfFDvNZECgYEAp1/wY9NXjX4AYiIPkiGykZjI186OFvUhX++mD2fqln8EtuvE
yRHPHjvGVYo1dO69vMQZMEm4w3dvsBEbABly3LDcTn4EDhc3EoF5ZIHRuZ9LHgJf
i0aBTxGZ3r774MYwptlcR/c7mCPN1DFEeL9rwMUwKaSJPRDNrQKGLvwm2CUCgYBK
LBN4GKiH4gCiwYuuQxvp+1WKPU+MBf5fsIbewnpoE1NdJVRuPWD97UyqfMz8l9K3
VCnj+OMqNTkhYcIDf46Zt5ca1jj4FK88FCHSIiULCO6DUJKO4NCoa+US98fu58dd
2n5PUQy0b97L1xvRj5lWpK6dx6bSHmipgE9MnwlKcQKBgQCZR2Czs0O/fi1V0Ecl
d1XDDCAS3sECclhqiJkcn9TaM/0chGR7E//0ChP82ca5ihkByVgsOfaYaWZg+Eci
FUQep3DnjONc0kX9xeiSn3Z2jbUMcoub/uY0OWreE+3FL1ZgjYs1KKdUOWF2DL/X
L7en4sepnWifRGs2gnPYKrn1Zg==
-----END PRIVATE KEY-----
'''

if __name__ == "__main__":
    main()
