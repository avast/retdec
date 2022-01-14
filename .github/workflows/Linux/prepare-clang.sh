#!/usr/bin/bash

wget --no-proxy https://releases.llvm.org/3.9.1/clang+llvm-3.9.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz -O llvm.tar.xz
tar -xJf llvm.tar.xz
mv clang* $CLANG_DIR_OUT
