#!/usr/bin/bash

export PATH="/usr/local/opt/openssl@1.1/bin:$PATH"
export OPENSSL_ROOT_DIR="/usr/local/opt/openssl@1.1/"

RD_DIR=$PWD
mkdir -p build
cd build

cmake $RD_DIR -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DRETDEC_TESTS=on -DCMAKE_INSTALL_PREFIX=$RD_DIR/install
make -j$(sysctl -n hw.ncpu) install
