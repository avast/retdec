#!/usr/bin/bash

wget --no-proxy https://releases.llvm.org/3.9.0/clang+llvm-3.9.0-x86_64-apple-darwin.tar.xz -O llvm.tar.xz
tar -xJf llvm.tar.xz
mv clang* $CLANG_DIR_OUT
