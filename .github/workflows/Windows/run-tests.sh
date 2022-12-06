set -x

IGNORE_TESTS=$(cat $1 | tr -d '\r' | tr '\n' ',' | sed 's/,$//' | tr '.' '\\')

# We need to specify each path in Windows format.
WIN_PWD=D:$(echo $PWD | sed 's/^\/d//' | sed 's/\//\\/g')

cat <<EOF > $PWD/retdec-regression-tests-framework/config_local.ini
[runner]
; Path to the extracted Clang package containing subdirectories such as bin, include, lib, share.
clang_dir = $WIN_PWD\\clang
; Path to the cloned repository containing regression tests.
tests_root_dir = $WIN_PWD\\retdec-regression-tests
; Path to the RetDec's installation directory.
retdec_install_dir = $WIN_PWD\\install
; Exclude directories
excluded_dirs = $IGNORE_TESTS
EOF

cd "$PWD/retdec-regression-tests-framework"

python -m pip install virtualenv
python -m venv .venv

. .venv/Scripts/activate
pip3 install -r requirements.txt

python3 ./runner.py
