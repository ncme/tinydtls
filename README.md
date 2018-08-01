tinyDTLS (generic short Weierstrass ECC fork)
=======
Tinydtls is a library for Datagram Transport Layer Security (DTLS) covering both the client and the server state machine. It is implemented in C and provides support for the mandatory cipher suites specified in [CoAP](https://tools.ietf.org/html/rfc7252).

This version of the library modifies the ECC functions to support generic short Weierstrass curves and adds the curve Wei25519 that is birationally equivalent to Curve25519 and Ed25519.

## CONTENTS

This library contains functions and structures that can help constructing a single-threaded UDP server with DTLS support in C99. The following components are available:
* **dtls**
   Basic support for DTLS with pre-shared key mode and RPK mode with ECC.
* **tests**
  The subdirectory tests contains test programs that show how each component is used.

## BUILDING

When using the code from the git repository at sourceforge, invoke

    $ autoconf
    $ autoheader
    $ ./configure

to re-create the configure script.

On Contiki, place the tinydtls library into the apps folder. After configuration, invoke make to build the library and associated test programs. To add tinydtls as Contiki application, drop it into the apps directory and add the following line to your Makefile:

    APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls
