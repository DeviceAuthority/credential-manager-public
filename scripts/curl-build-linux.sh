#!/bin/bash

showusage() {
  echo "Script to cross compile CURL"
  echo "Usage: ./curl-build-linux.sh [OPTION]"
  echo "OPTION:"
  echo "  --with-ssl                   Build CURL with SSL support"
  echo "  --without-ssl                Build CURL without SSL support"
  echo "  -h, --help                   Display this help and exit"
  exit 1
}

withssl=0
curlopt="--disable-ldap --disable-ntlm-wb"
curlver="8.2.0"
opensslver="3.0.9"

## Parse arguments
while [ "$1" != "" ]; do
  case $1 in
    --with-ssl)
      withssl=1
      curlopt="${curlopt} --with-openssl"
      ;;
    --without-ssl)
      curlopt="${curlopt} $1"
      ;;
    -h | --help)
      showusage
      ;;
    *)
      echo "Invalid argument $1. Please use -h for help."; exit 1
  esac
  shift
done

if [ -L curl ]; then
  echo "Removing symbolic link curl"
  rm -f curl
fi
if [ -d curl-${curlver} ]; then
  echo "Removing curl-${curlver} directory..."
  rm -rf curl-${curlver}
  rc=$?
  if [ $? -ne 0 ]; then
    echo "ERR: Failed to remove curl-${curlver} directory"
    exit $rc
  fi
fi

if [ ! -f curl-${curlver}.tar.gz ]; then
  echo "Downloading curl-${curlver}.tar.gz from http://curl.haxx.se..."
  wget http://curl.haxx.se/download/curl-${curlver}.tar.gz
  rc=$?
else
  rc=0
  echo "Found curl-${curlver}.tar.gz. curl download skipped"
fi
if [ $rc -eq 0 ] && [ -f curl-${curlver}.tar.gz ]; then
  echo "Extracting curl-${curlver}.tar.gz..."
  tar -xzvf curl-${curlver}.tar.gz
  rc=$?
  if [ $? -ne 0 ]; then
    echo "ERR: Failed extracting curl-${curlver}.tar.gz"
    exit $rc
  fi
  rm curl-${curlver}.tar.gz
fi

export ROOTDIR="${PWD}"
export INSTALLDIR="${ROOTDIR}/curl-${curlver}/final"
export TARGETMACH=${TOOLCHAIN}
export BUILDMACH=i686-pc-linux-gnu
export AR=${CROSS_COMPILE}ar
export AS=${CROSS_COMPILE}as
export LD=${CROSS_COMPILE}ld
export RANLIB=${CROSS_COMPILE}ranlib
export CC=${CROSS_COMPILE}gcc
export NM=${CROSS_COMPILE}nm
CFLAGS="-ffunction-sections -fdata-sections"
CPPFLAGS="-ffunction-sections -fdata-sections"
LIBS=""
LDFLAGS="-Wl,--gc-sections"
if [ $withssl -eq 1 ]; then
  LIBS="${LIBS} -lssl -lcrypto"
  CFLAGS="${CFLAGS}"
  CPPFLAGS="${CPPFLAGS} -I${ROOTDIR}/third_party/openssl/include"
  LDFLAGS="${LDFLAGS} -L${ROOTDIR}/third_party/openssl/lib"
fi
export CFLAGS
export CPPFLAGS
export LIBS
export LDFLAGS

echo "Entering curl-${curlver} directory..."
pushd curl-${curlver} > /dev/null
echo "Configuring CURL..."
./configure --prefix=${INSTALLDIR} --build=${BUILDMACH} --host=${TARGETMACH} ${curlopt}
rc=$?
if [ $rc -ne 0 ]; then
  echo "ERR: Something went wrong during configure"
  echo "Leaving curl-${curlver} directory..."
  popd > /dev/null
  exit $rc
fi
echo "Cross compiling CURL..."
make
rc=$?
if [ $rc -ne 0 ]; then
  echo "ERR: Something went wrong during cross compilation"
  echo "Leaving curl-${curlver} directory..."
  popd > /dev/null
  exit $rc
fi
echo "Installing CURL..."
make install
echo "Leaving curl-${curlver} directory..."
popd
if [ -d curl-${curlver} ]; then
  mkdir -p third_party/curl
  cp -r curl-${curlver}/final/include third_party/curl
  cp -r curl-${curlver}/final/lib third_party/curl
else
  echo "WARN: curl-${curlver} file or directory not found"
fi

# Tidy up
rm -r curl-${curlver}/
