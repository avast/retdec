#!/usr/bin/bash

curl https://releases.llvm.org/3.9.1/LLVM-3.9.1-win64.exe -o llvm.exe

# Save download path.
download_path=$PWD

# Create output dir for clang.
mkdir -p $CLANG_DIR_OUT
cd $CLANG_DIR_OUT

# Extract clang there.
7z x $download_path/llvm.exe
