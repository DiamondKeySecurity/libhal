libhal
======

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

* An implementation of PBPDF2.

* An implementation of RSA using the Cryptech ModExp core.

* Test code for all of the above.

Most of these are fairly well self-contained, although the PBKDF2
implementation uses the hash-core-based HMAC implementation.

The major exception is the RSA implementation, which uses an external
bignum implementation (libtfm) to handle a lot of the arithmetic.  In
the long run, much or all of this may end up being implemented in
Verilog, but for the moment all of the RSA math except for modular
exponentiation is happening in software.

The RSA implementation includes a compile-time option to bypass the
ModExp core and do everything in software, because the ModExp core is
a tad slow at the moment (others are hard at work fixing this).

The RSA implementation includes optional blinding (enabled by default)
and just enough ASN.1 code to read and write private keys; the
expectation is that the latter will be used in combination with the
AES Key Wrap code.
