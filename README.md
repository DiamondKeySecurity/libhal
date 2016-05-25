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

* Low-level I/O code (EIM and I2C).

* An implementation of AES Key Wrap using the Cryptech AES core.

* An interface to the Cryptech CSPRNG.

* An interface to the Cryptech hash cores, including HMAC.

* An implementation of PBKDF2.

* An implementation of RSA using the Cryptech ModExp core.

* An implementation of ECDSA, currently entirely in software.

* Test code for all of the above.

Most of these are fairly well self-contained, although the PBKDF2
implementation uses the hash-core-based HMAC implementation.

The major exceptions are the RSA and ECDSA implementations, which uses
an external bignum implementation (libtfm) to handle a lot of the
arithmetic.  In the long run, much or all of this may end up being
implemented in Verilog, but for the moment all of the RSA math except
for modular exponentiation is happening in software, as is all of the
math for ECDSA.

## RSA ##

The RSA implementation includes a compile-time option to bypass the
ModExp core and do everything in software, because the ModExp core is
a tad slow at the moment (others are hard at work fixing this).

The RSA implementation includes optional blinding (enabled by default)
and just enough ASN.1 code to read and write private keys; the
expectation is that the latter will be used in combination with the
AES Key Wrap code.

## ECDSA ##

The ECDSA implementation is specific to the NIST prime curves P-256,
P-384, and P-521.

The ECDSA implementation includes a compile-time option to allow test
code to bypass the CSPRNG in order to test against known test vectors.
Do **NOT** enable this in production builds, as ECDSA depends on good
random numbers not just for private keys but for individual
signatures, and an attacker who knows the random number used for a
particular signature can use this to recover the private key.
Arguably, this option should be removed from the code entirely, once
the implementation is stable.

The ECDSA implementation includes enough ASN.1 to read and write ECDSA
signatures and ECDSA private keys in RFC 5915 format; the expectation
is that the latter will be used in combination with AES Key Wrap.

The ECDSA implementation attempts to be constant-time, to reduce the
risk of timing channel attacks.  The algorithms chosen for the point
arithmetic are a tradeoff between speed and code complexity, and can
probably be improved upon even in software; reimplementing at least
the field arithmetic in hardware would probably also help.

The current point addition and point doubling algorithms come from the
[EFD][].  At least at the moment, we're only interested in ECDSA with
the NIST prime curves, so we use algorithms optimized for a=-3.

The point multiplication algorithm is a straightforward double-and-add
loop, which is not the fastest possible algorithm, but is relatively
easy to confirm by inspection as being constant-time within the limits
imposed by the NIST curves.  Point multiplication could probably be
made faster by using a non-adjacent form (NAF) representation for the
scalar, but the author doesn't yet understand that well enough to
implement it as a constant-time algorithm.  In theory, changing to a
NAF representation could be done without any change to the public API.

Points stored in keys and curve parameters are in affine format, but
point arithmetic is performed in Jacobian projective coordinates, with
the coordinates themselves in Montgomery form; final mapping back to
affine coordinates also handles the final Montgomery reduction.

## API ##

Yeah, we ought to document the API, Real Soon Now, perhaps using
[Doxygen][].  For the moment, see the function prototypes in hal.h and
comments in the code.

[EFD]:		http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
[Doxygen]:	http://www.doxygen.org/
