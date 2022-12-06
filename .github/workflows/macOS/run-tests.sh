#!/usr/bin/bash

set -x

IGNORE_TESTS=$(cat $1 | tr '\n' ',' | sed 's/,$//' | tr '.' '/')

cat <<EOF > $PWD/retdec-regression-tests-framework/config_local.ini
[runner]
; Path to the extracted Clang package containing subdirectories such as bin, include, lib, share.
clang_dir = $PWD/clang
; Path to the cloned repository containing regression tests.
tests_root_dir = $PWD/retdec-regression-tests
; Path to the RetDec's installation directory.
retdec_install_dir = $PWD/install

; 2019-09-05: On macOS, we have to skip tests that compile output C files
; because newer Xcode versions no longer support compilation into 32b binaries:
;
; "The macOS 10.14 SDK no longer contains support for compiling 32-bit applications.
;  If developers need to compile for i386, Xcode 9.4 or earlier is required."
;
; We cannot compile into 64b binaries because of RetDec shortcomings
; (https://github.com/avast/retdec/issues/213). So, we decided to skip tests that
; compile output C files when running regression tests on macOS.
skip_c_compilation_tests = 0
; Exclude directories
excluded_dirs = $IGNORE_TESTS
EOF

cd "$PWD/retdec-regression-tests-framework"

python3 -m venv .venv

. .venv/bin/activate
pip3 install -r requirements.txt

python3 ./runner.py
