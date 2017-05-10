libhal
======

## Overview ##

This library combines a set of low-level API functions which talk to
the Cryptech FPGA cores with a set of higher-level functions providing
various cryptographic services.

There's some overlap between the low-level code here and the low-level
code in core/platform/novena, which will need sorting out some day,
but at the time this library forked that code, the
core/platform/novena code was all written to support a test harness
rather than a higher-level API.

Current contents of the library:

* Low-level I/O code (FMC, EIM, and I2C).

* An implementation of AES Key Wrap using the Cryptech AES core.

* An interface to the Cryptech CSPRNG.

* An interface to the Cryptech hash cores, including HMAC.

* An implementation of PBKDF2.

* An implementation of RSA, optionally using the Cryptech ModExp core.

* An implementation of ECDSA, optionally using the Cryptech ECDSA base
  point multiplier cores.

* An interface to the Master Key Memory interface core on the Cryptech
  Alpha platform.

* A simple keystore implementation with drivers for RAM and flash
  storage on the Cryptech Alpha platform.

* A remote procedure call (RPC) interface.

* (Just enough) ASN.1 code to support a uniform interface to public
  (SubjectPublicKeyInformation (SPKI)) and private (PKCS #8) keys.

* A simple key backup mechanism, including a Python script to drive it
  from the client side.

* An RPC multiplexer to allow multiple clients (indepedent processes)
  to talk to the Cryptech Alpha at once.

* Client implenetations of the RPC mechanism in both C and Python.

* Test code for all of the above.

Most of these are fairly well self-contained, although the PBKDF2
implementation uses the hash-core-based HMAC implementation with
fallback to a software implementation if the cores aren't available.

The major exceptions are the RSA and ECDSA implementations, which uses
an external bignum implementation (libtfm) to handle a lot of the
arithmetic.  In the long run, much or all of this may end up being
implemented in Verilog, but for the moment all of the RSA math except
for modular exponentiation is happening in software, as is all of the
math for ECDSA verification; ECDSA math for key generation and signing
on the P-256 and P-384 curves is done in the ECDSA base point
multiplier cores when those are available.

## RSA ##

The RSA implementation includes a compile-time option to bypass the
ModExp core and do everything in software, because the ModExp core is
a tad slow at the moment (others are hard at work fixing this).

The RSA implementation includes optional blinding (enabled by default).

## ECDSA ##

The ECDSA implementation is specific to the NIST prime curves P-256,
P-384, and P-521.

The ECDSA implementation includes a compile-time option to allow test
code to bypass the CSPRNG in order to test against known test vectors.
Do **NOT** enable this in production builds, as ECDSA depends on good
random numbers not just for private keys but for individual
signatures, and an attacker who knows the random number used for a
particular signature can use this to recover the private key.
Arguably, this option should be removed from the code entirely.

The ECDSA software implementation attempts to be constant-time, to
reduce the risk of timing channel attacks.  The algorithms chosen for
the point arithmetic are a tradeoff between speed and code complexity,
and can probably be improved upon even in software; reimplementing at
least the field arithmetic in hardware would probably also help.
Signing and key generation performance is significantly better when
the ECDSA base point multiplier cores are available.

The point addition and point doubling algorithms in the current ECDSA
software implementation come from the [EFD][].  At least at the
moment, we're only interested in ECDSA with the NIST prime curves, so
we use algorithms optimized for a=-3.

The point multiplication algorithm is a straightforward double-and-add
loop, which is not the fastest possible algorithm, but is relatively
easy to confirm by inspection as being constant-time within the limits
imposed by the NIST curves.  Point multiplication could probably be
made faster by using a non-adjacent form (NAF) representation for the
scalar, but the author doesn't understand that well enough to
implement it as a constant-time algorithm.  In theory, changing to a
NAF representation could be done without any change to the public API.

Points stored in keys and curve parameters are in affine format, but
point arithmetic is performed in Jacobian projective coordinates, with
the coordinates themselves in Montgomery form; final mapping back to
affine coordinates also handles the final Montgomery reduction.

## Key backup ##

The key backup mechanism is a straightforward three-step process,
mediated by a Python script which uses the Python client
implementation of the RPC mechanism.  Steps:

1. Destination HSM (target of key transfer) generates an RSA keypair,
   exports the public key (the "key encryption key encryption key" or
   "KEKEK").

2. Source HSM (origin of the key transfer) wraps keys to be backed up
   using AES keywrap with key encryption keys (KEKs) generated by the
   TRNG; these key encryption keys are in turn encrypted with RSA
   public key (KEKEK) generated by the receipient HSM.

3. Destination HSM receives wrapped keys, unwraps the KEKs using the
   KEKEK then unwraps the wrapped private keys.

Transfer of the wrapped keys between the two HSMs can be by any
convenient mechanism; for simplicity, `cryptech_backup` script bundles
everything up in a text file using JSON and Base64 encoding.

## Multiplexer daemon ##

While the C client library can be built to talk directly to the
Cryptech Alpha board, in most cases it is more convenient to use the
`cryptech_muxd` multiplexer daemon, which is now the default.  Client
code talks to `cryptech_muxd` via a `PF_UNIX` socket; `cryptech_muxd`
handles interleaving of messages between multiple clients, and also
manages access to the Alpha's console port.

The multiplexer requires two external Python libraries, Tornado
(version 4.0 or later) and PySerial (version 3.0 or later).

In the long run, the RPC mechanism will need to be wrapped in some
kind of secure channel protocol, but we're not there yet.

## API ##

Yeah, we ought to document the API, Real Soon Now, perhaps using
[Doxygen][].  For the moment, see the function prototypes in hal.h,
the Python definitions in cryptech.libhal, and and comments in the
code.

[EFD]:		http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
[Doxygen]:	http://www.doxygen.org/
