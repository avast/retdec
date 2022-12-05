#!/usr/bin/bash

RD_DIR=$PWD

# The C:/ drive on Windows has significanly larger space to work with.
mkdir -p /c/build
cd /c/build

cmake $RD_DIR -DRETDEC_TESTS=on -DCMAKE_INSTALL_PREFIX="$RD_DIR/install" -DRETDEC_DEV_TOOLS=ON
cmake --build . -j $NUMBER_OF_PROCESSORS --config $BUILD_TYPE -- -m
cmake --build . --config $BUILD_TYPE --target "$PWD/install"
