# Credential Management

Further information on this project can be found on our developer pages at https://deviceauthority.com/developers/

## Pre-requisites

The following packages are required to build Credential Manager on a typical Linux distribution:

- git
- build-essential
- zliblg-dev

## Building third-party libraries

### OpenSSL

To build openSSL we provide a script, openssl-build-linux.sh. Run this script using the following commands:

`scripts/openssl-build-linux.sh --version <version number>`

where \<version number\> is the version of openSSL, e.g. `3.0.9`.

This generates the required library and include files in the `third_party/openssl/` directory.

### cURL

To build cURL we provide the script `curl-build-linux.sh`. Run this script using the following commands:

`scripts/curl-build-linux.sh --with-ssl`

This generates the required library and include files in the `third_party/curl/` directory.

Note that this requires openSSL to have been compiled as it utilises the paths `third_party/openssl/lib` and `third_party/openssl/include` in its build flags.

## Building credential-management

To build credential management run `make -j4`

## How to cross-compile credential-management

Configure the toolchain for cross compiling within the setenv.sh script. For example, targetting a Raspberry PI 2 using 
crosstools-ng we would configure setenv.sh as follows:

```sh
export TOOLCHAIN=armv7-rpi2-linux-gnueabihf
TOOLCHAINDIR=/usr/local/x-tools/${TOOLCHAIN}
export PATH=$PATH:${TOOLCHAINDIR}/bin
export DEVKIT=${TOOLCHAINDIR}/${TOOLCHAIN}/sysroot
export CROSS_CFLAGS=""
export CROSS_CXXFLAGS=""
export CROSS_COMPILE=${TOOLCHAIN}-
export CROSS_CPU=ARMv7
```

This uses the crosstools-ng sample toolchain `armv7-rpi2-linux-gnueabihf` and builds for an `ARMv7` CPU instruction set.

_Note: you need to replace the supplied libraries in third_party/ with library files built for your target architecture._

# DDKG libraries

We have included DDKG builds for Linux and Windows for the x64 architecture. These are available in `DDKG/linux/x64` and `DDKG/windows/x64` directories.