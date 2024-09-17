#!/bin/bash

showusage() {
  echo "Script to cross compile OpenSSL"
  echo "Usage: ./${0##*/} [OPTION]"
  echo "OPTION:"
  echo "  -h, --help                   Display this message and exit"
  echo "  --version <version>          Specify OpenSSL version to use. Default is version 3.0.9"
  echo
  exit 0
}

opensslver="3.0.9"

## Parse arguments
while [ "$1" != "" ]; do
  case $1 in
    -h | --help)
      showusage
      ;;
    --version)
      shift
      opensslver=$1
      ;;
    *)
      echo "ERR: Invalid argument $1. Please use -h for help."; exit 1
  esac
  shift
done

echo
echo "OpenSSL version: ${opensslver}"
echo

if [ -d openssl-${opensslver} ]; then
  echo "Removing openssl-${opensslver} directory..."
  rm -rf openssl-${opensslver}
fi
if [ ! -f openssl-${opensslver}.tar.gz ]; then
  echo "Downloading openssl-${opensslver}.tar.gz from https://www.openssl.org..."
  wget https://www.openssl.org/source/openssl-${opensslver}.tar.gz
  rc=$?
  if [ $rc -ne 0 ]; then
    wget https://www.openssl.org/source/old/1.0.1/openssl-${opensslver}.tar.gz
    rc=$?
  fi
else
  rc=0
  echo "Found openssl-${opensslver}.tar.gz. OpenSSL download skipped"
fi

if [ $rc -eq 0 ] && [ -f openssl-${opensslver}.tar.gz ]; then
  echo "Unarchiving openssl-${opensslver}.tar.gz..."
  tar -xzf openssl-${opensslver}.tar.gz
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "ERR: Failed extracting openssl-${opensslver}.tar.gz"
    exit $rc
  fi
  rm openssl-${opensslver}.tar.gz
fi

openssl11=0
openssl30x=0
versions=(${opensslver//./ })
oscomplier="os/compiler:${CROSS_COMPILE}"
if [ ${versions[0]} == "3" ]; then
  if [ ${versions[1]} == "0" ]; then
    openssl30x=1
  fi
elif [ ${versions[0]} == "1" ]; then
  if [ ${versions[1]} == "1" ]; then
    openssl11=1
    oscompiler="linux-generic64"
  fi
fi

export ROOTDIR="${PWD}"
export INSTALLDIR="${ROOTDIR}/openssl-${opensslver}/final"
export PATH=$INSTALLDIR/bin:$PATH
export TARGETMACH={$TOOLCHAIN}
export BUILDMACH=i686-pc-linux-gnu
export CC=${CROSS}gcc
export LD=${CROSS}ld
export AS=${CROSS}as
export AR=${CROSS}ar
export NM=${CROSS_COMPILE}nm
export RANLIB=${CROSS_COMPILE}ranlib
export CFLAGS="-ffunction-sections -fdata-sections"
export CXXFLAGS="-ffunction-sections -fdata-sections"
export LDFLAGS="-Wl,--gc-sections"

if [ ! -d openssl-${opensslver} ]; then
  echo "ERR: openssl-${opensslver} file or directory not found"
  exit 1
fi
echo "Entering openssl-${opensslver} directory..."
cd openssl-${opensslver} > /dev/null
echo "Configuring OpenSSL..."
if [ ${openssl30x} -eq 1 ]; then
  echo "./config shared no-asm --prefix=${INSTALLDIR} ${CFLAGS} ${LDFLAGS}"
  ./config shared no-asm --prefix=${INSTALLDIR} ${CFLAGS} ${LDFLAGS}
elif [ ${openssl11} -eq 1 ]; then
  echo "./config shared no-asm --prefix=${INSTALLDIR} ${CFLAGS} ${LDFLAGS}"
  ./config shared no-asm --prefix=${INSTALLDIR} ${CFLAGS} ${LDFLAGS}
else
  echo "./config shared no-asm --prefix=${INSTALLDIR} -DOPENSSL_NO_HEARTBEATS ${CFLAGS} ${LDFLAGS}"
  ./config shared no-asm --prefix=${INSTALLDIR} -DOPENSSL_NO_HEARTBEATS ${CFLAGS} ${LDFLAGS}
fi
rc=$?
if [ $rc -ne 0 ]; then
  echo "ERR: Something went wrong during configure"
  echo "Leaving openssl-${opensslver} directory..."
  cd ..
  exit $rc
fi
echo "Making dependencies..."
make depend
rc=$?
if [ $rc -ne 0 ]; then
  echo "ERR: Something went wrong during make depend"
  echo "Leaving openssl-${opensslver} directory..."
  cd ..
  exit $rc
fi
echo "Cross compiling OpenSSL..."
make
rc=$?
if [ $rc -ne 0 ]; then
  echo "ERR: Something went wrong during cross compile"
  echo "Leaving openssl-${opensslver} directory..."
  cd ..
  exit $rc
fi
echo "Installing OpenSSL..."
make install_sw
echo "Leaving openssl-${opensslver} directory..."
cd ..
if [ -d openssl-${opensslver} ]; then
  mkdir -p third_party/openssl/lib
  if [ -d "openssl-${opensslver}/final/lib64/" ]; then
    cp openssl-${opensslver}/final/lib64/*.so* third_party/openssl/lib
  elif [ -d "openssl-${opensslver}/final/lib/" ]; then
    cp openssl-${opensslver}/final/lib/*.so* third_party/openssl/lib
  else 
    echo "ERR: Failed to find openssl library files."
    exit -1
  fi
  cp -r openssl-${opensslver}/final/include third_party/openssl/
else
  echo "WARN: openssl-${opensslver} file or directory not found"
fi

# Tidy up
rm -r openssl-${opensslver}/