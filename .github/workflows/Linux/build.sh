#!/usr/bin/bash

RD_DIR=$PWD
mkdir -p build
cd build

cmake $RD_DIR -DCMAKE_BUILD_TYPE=$BUILD_TYPE -DRETDEC_TESTS=on -DCMAKE_INSTALL_PREFIX=$RD_DIR/install
make -j$(nproc) install
