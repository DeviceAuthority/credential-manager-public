#!/bin/bash

showusage() {
  echo "Script to download and deploy RapidJSON"
  echo "Usage: ./${0##*/} [OPTION]"
  echo "OPTION:"
  echo "  -h, --help                   Display this message and exit"
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
    *)
      echo "ERR: Invalid argument $1. Please use -h for help."; exit 1
  esac
  shift
done

echo
echo "Downloading RapidJSON"
echo

if [ -d third_party/rapidjson ]; then
  rm -rf third_party/rapidjson
fi

if [ ! -f v1.0.2.tar.gz ]; then
  echo "Downloading RapidJSON v1.0.2.tar.gz from https://github.com/Tencent/rapidjson/..."
  wget https://github.com/Tencent/rapidjson/archive/refs/tags/v1.0.2.tar.gz
  rc=$?
else
  echo "Found v1.0.2.tar.gz. RapidJSON download skipped"
  rc=0
fi

if [ $rc -eq 0 ] && [ -f v1.0.2.tar.gz ]; then
  echo "Unarchiving RapidJSON v1.0.2.tar.gz..."
  tar -xzf v1.0.2.tar.gz
  rc=$?
  if [ $rc -ne 0 ]; then
    echo "ERR: Failed extracting v1.0.2.tar.gz"
    exit $rc
  fi
  mv rapidjson-1.0.2 third_party/rapidjson
  rm v1.0.2.tar.gz
fi