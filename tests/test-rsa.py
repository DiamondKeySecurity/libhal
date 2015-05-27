# Use PyCrypto to generate test data for Cryptech ModExp core.
#
# Funnily enough, PyCrypto and Cryptlib use exactly the same names for
# RSA key components, see Cryptlib documentation pages 186-187 & 339.

key_lengths = (1024, 2048, 4096)        # Lengths in bits of keys to generate
pkcs_encoding = 8                       # PKCS encoding for PEM comment (1 or 8)

plaintext = "You can hack anything you want with TECO and DDT."

from Crypto                             import __version__ as PyCryptoVersion
from Crypto.PublicKey                   import RSA
from Crypto.Hash                        import SHA256
from Crypto.Util.number                 import long_to_bytes
from Crypto.Signature.PKCS1_v1_5        import EMSA_PKCS1_V1_5_ENCODE, PKCS115_SigScheme
from textwrap                           import TextWrapper
import sys, os.path

assert all(key_length % 8 == 0 for key_length in key_lengths)

scriptname = os.path.basename(sys.argv[0])

wrapper = TextWrapper(width = 78, initial_indent = " " * 2, subsequent_indent = " " * 2)

def printlines(*lines, **kwargs):
  for line in lines:
    sys.stdout.write(line % kwargs + "\n")

def trailing_comma(item, sequence):
  return "" if item == sequence[-1] else ","

def print_hex(name, value, comment):
  printlines("static const uint8_t %(name)s[] = { /* %(comment)s, %(length)d bytes */",
             wrapper.fill(", ".join("0x%02x" % ord(v) for v in value)),
             "};", "",
             name = name, comment = comment, length  = len(value))

h = SHA256.new(plaintext)

printlines("/*",
           " * RSA signature test data for Cryptech project, automatically generated by",
           " * %(scriptname)s using PyCrypto version %(version)s. Do not edit.",
           " *",
           " * Plaintext: \"%(plaintext)s\"",
           " * SHA-256: %(digest)s",
           " */", "",
           scriptname = scriptname,
           version    = PyCryptoVersion,
           plaintext  = plaintext,
           digest     = h.hexdigest())

for k_len in key_lengths:

  k = RSA.generate(k_len)       # Cryptlib insists u < p, probably with good reason,
  while k.u >= k.p:             # and I'm sure not going to argue the math with Peter,
    k = RSA.generate(k_len)     # so keep trying until we pass this test

  m = EMSA_PKCS1_V1_5_ENCODE(h, k_len/8)
  s = PKCS115_SigScheme(k).sign(h)
  assert len(m) == len(s)

  printlines("/* %(k_len)d-bit RSA private key (PKCS #%(pkcs)d)",
             k.exportKey(format = "PEM", pkcs = pkcs_encoding),
             "*/", "",
             k_len = k_len, pkcs  = pkcs_encoding)

  for component in k.keydata:
    print_hex("%s_%d" % (component, k_len),
              long_to_bytes(getattr(k, component), blocksize = 4),
              "key component %s" % component)
  print_hex("m_%d" % k_len, m, "message to be signed")
  print_hex("s_%d" % k_len, s, "signed message")

fields = "nedpqums"
printlines("typedef struct { const uint8_t *val; size_t len; } rsa_tc_bn_t;",
           "typedef struct { size_t size; rsa_tc_bn_t %(fields)s; } rsa_tc_t;",
           "",
           "static const rsa_tc_t rsa_tc[] = {",
           fields = ", ".join(fields))
for k_len in key_lengths:
  printlines("  { %(k_len)d,", k_len = k_len)
  for field in fields:
    printlines("    { %(field)s_%(k_len)d, sizeof(%(field)s_%(k_len)d) }%(comma)s",
               field = field, k_len = k_len, comma = trailing_comma(field, fields))
  printlines("  }%(comma)s", comma = trailing_comma(k_len, key_lengths))
printlines("};")
