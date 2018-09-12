tinyDTLS (generic short Weierstrass ECC fork)
=======
Tinydtls is a library for Datagram Transport Layer Security (DTLS) covering both the client and the server state machine. It is implemented in C and provides support for the mandatory cipher suites specified in [CoAP](https://tools.ietf.org/html/rfc7252).

This version of the library modifies the ECC functions to support generic short Weierstrass curves and adds the curve Wei25519 that is birationally equivalent to Curve25519 and Ed25519.

## USAGE

Use the new API function `int ecc_ec_init(const ec_curve_t curve)` to switch between curves. Supported curves are `SECP256R1` (default), `WEI25519` and `WEI25519_2`.
For a reference on how to use the curve model transformations from `convert.h` see `testconvert.c`.

To test the conversions against another library, build and link the [C25519](https://github.com/ncme/c25519) with `testconvert.c` and set the build variable `WITH_C25519`.

## BUILDING

When using the code from the git repository at sourceforge, invoke

    $ autoconf
    $ autoheader
    $ ./configure

to re-create the configure script.

On Contiki, place the tinydtls library into the apps folder. After configuration, invoke make to build the library and associated test programs. To add tinydtls as Contiki application, drop it into the apps directory and add the following line to your Makefile:

    APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls
