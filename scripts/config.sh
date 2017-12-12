#!/bin/bash
#
# Decompiler's configuration. This file should be included in every decompilation script.
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_CONFIG" ]; then
	DECOMPILER_CONFIG="./config.sh"
fi

#
# Detect OS type (win / linux / linux64)
#
get_SYS()
{
	if [[ $(uname -s) == *Linux* ]]; then
		echo "linux"
	elif [[ $(uname -s) == *MINGW* ]] || [[ $(uname -s) == *MSYS* ]]; then
		echo "win"
	else
		echo "unknown"
	fi
}

##
## Settings.
##
SYS="$(get_SYS)"
if [ "$SYS" != "win" -a "$SYS" != "linux" ]; then
	echo "Error: Unknown OS" >&2
	exit 1
fi

##
## Paths (everything has to be without the ending slash '/').
##

# Paths relative from script path.
INSTALL_BIN_DIR="$SCRIPTPATH"
UNIT_TESTS_DIR="$INSTALL_BIN_DIR/unit-tests"
UNPACKER_PLUGINS_DIR="$INSTALL_BIN_DIR/unpacker-plugins"
INSTALL_SHARE_DIR="$INSTALL_BIN_DIR/../share"
INSTALL_SHARE_YARA_DIR="$INSTALL_SHARE_DIR/generic/yara_patterns"

## generic configuration
GENERIC_TYPES_DIR="$INSTALL_SHARE_DIR/generic/types"
GENERIC_SIGNATURES_DIR="$INSTALL_SHARE_DIR/generic/yara_patterns/static-code"

## ARM-specific configuration
ARM_ORDS_DIR="$INSTALL_SHARE_DIR/arm/ords"

## X86-specific configuration
X86_ORDS_DIR="$INSTALL_SHARE_DIR/x86/ords"

## BIN2LLVMIR parameters
# The following list of passes is -O3
#   * with -disable-inlining -disable-simplify-libcalls -constprop -die -dce -ipconstprop -instnamer
#   * without -internalize -inline -inline-cost -notti -deadargelim -argpromotion -simplify-libcalls -loop-unroll -loop-unswitch -sroa -tailcallelim -functionattrs -memcpyopt -prune-eh
BIN2LLVMIR_PARAMS_DISABLES="-disable-inlining -disable-simplify-libcalls"
BIN2LLVMIR_ONLY_PASSES="-instcombine -tbaa -targetlibinfo -basicaa -domtree -simplifycfg -domtree -early-cse -lower-expect -targetlibinfo -tbaa -basicaa -globalopt -mem2reg -instcombine -simplifycfg -basiccg -domtree -early-cse -lazy-value-info -jump-threading -correlated-propagation -simplifycfg -instcombine -simplifycfg -reassociate -domtree -loops -loop-simplify -lcssa -loop-rotate -licm -lcssa -instcombine -scalar-evolution -loop-simplifycfg -loop-simplify -aa -loop-accesses -loop-load-elim -lcssa -indvars -loop-idiom -loop-deletion -memdep -gvn -memdep -sccp -instcombine -lazy-value-info -jump-threading -correlated-propagation -domtree -memdep -dse -dce -bdce -adce -die -simplifycfg -instcombine -strip-dead-prototypes -globaldce -constmerge -constprop -instnamer -domtree -instcombine"
BIN2LLVMIR_VOLATILIZED_PASSES="-volatilize -instcombine -reassociate -volatilize"
# Notes:
#
# - We run all the passes several times to produce more optimized results. The
# parameters beginning with -disable-* may be included only once, which is the
# reason of splitting $BIN2LLVMIR_PARAMS into several parts.
#
# -unreachable-funcs is automatically removed in decompile.sh when the
# -k/--keep-unreachable-funcs parameter is used.
#
# - We need to run -instcombine after -dead-global-assign to eliminate dead
# instructions after this optimization.
#
# - Optimization -phi2seq is needed to be run at the end and not to run two
# times. This is the reason why it is placed at the very end.
BIN2LLVMIR_PARAMS="$BIN2LLVMIR_PARAMS_DISABLES -inst-opt -verify $BIN2LLVMIR_VOLATILIZED_PASSES -control-flow -cfg-fnc-detect -main-detection -register -stack -control-flow -cond-branch-opt -syscalls -idioms-libgcc -constants -param-return -local-vars -type-conversions -simple-types -generate-dsm -remove-asm-instrs -select-fncs -unreachable-funcs -type-conversions -stack-protect -verify $BIN2LLVMIR_ONLY_PASSES -never-returning-funcs -adapter-methods -class-hierarchy $BIN2LLVMIR_ONLY_PASSES -simple-types -stack-ptr-op-remove -type-conversions -idioms -instcombine -global-to-local -dead-global-assign -instcombine -stack-protect -phi2seq"
# The following options are useful during debugging of bin2llvmirl optimizations.
#BIN2LLVMIR_PARAMS+="-print-after-all -debug-only=idioms -print-before=idioms -print-after=idioms"

FILEINFO="$INSTALL_BIN_DIR/fileinfo"
FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES=(
	"$INSTALL_SHARE_YARA_DIR/signsrch/signsrch.yara"
)
FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES=(
	"$INSTALL_SHARE_YARA_DIR/signsrch/signsrch_regex.yara"
)
AR="$INSTALL_BIN_DIR/ar-extractor"
BIN2PAT="$INSTALL_BIN_DIR/bin2pat"
PAT2YARA="$INSTALL_BIN_DIR/pat2yara"
CONFIGTOOL="$INSTALL_BIN_DIR/retdec-config"
EXTRACT="$INSTALL_BIN_DIR/macho-extractor"
DECOMPILE_SH="$INSTALL_BIN_DIR/decompile.sh"
DECOMPILE_ARCHIVE_SH="$INSTALL_BIN_DIR/decompile-archive.sh"
SIG_FROM_LIB_SH="$INSTALL_BIN_DIR/signature-from-library.sh"
UNPACK_SH="$INSTALL_BIN_DIR/unpack.sh"
LLVMIR2HLL="$INSTALL_BIN_DIR/llvmir2hll"
BIN2LLVMIR="$INSTALL_BIN_DIR/bin2llvmir"
IDA_COLORIZER="$INSTALL_BIN_DIR/color-c.py"
UNPACKER="$INSTALL_BIN_DIR/unpacker"

DEV_NULL="/dev/null"

# An alternative to the `time` shell builtin that provides more information. It
# is used in night tests to get the running time and used memory of a command.
TIME="/usr/bin/time -v"
