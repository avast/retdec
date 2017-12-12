#!/bin/bash
#
# The script tries to unpack the given executable file by using any
# of the supported unpackers, which are at present:
#    * generic unpacker
#    * upx
#
# Required argument:
#    * (packed) binary file
#
# Optional arguments:
#    * desired name of unpacked file
#    * use extended exit codes (mostly while executed via decompile.sh)
#
# Returns:
#  0 successfully unpacked
RET_UNPACK_OK=0
#  1 generic unpacker - nothing to do; upx succeeded (--extended-exit-codes only)
RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK=1
#  2 not packed or unknown packer
RET_NOTHING_TO_DO=2
#  3 generic unpacker failed; upx succeeded (--extended-exit-codes only)
RET_UNPACKER_FAILED_OTHERS_OK=3
#  4 generic unpacker failed; upx not succeeded
RET_UNPACKER_FAILED=4
# 10 other errors
#RET_OTHER_ERRORS=10

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_UTILS" ]; then
	DECOMPILER_UTILS="$SCRIPTPATH/utils.sh"
fi

. "$DECOMPILER_UTILS"

#
# Print help.
#
print_help()
{
	echo "Unpacking of the given executable file."
	echo ""
	echo "Usage:"
	echo "    $0 [ options ] file"
	echo ""
	echo "Options:"
	echo "    -h,        --help                 Print this help message."
	echo "    -e,        --extended-exit-codes  Use more granular exit codes than just 0/1."
	echo "    -o FILE,   --output FILE          Output file (default: file-unpacked)."
}

#
# Check proper combination of input arguments.
#
check_arguments()
{
	# Check whether the input file was specified.
	if [ -z "$IN" ]; then
		print_error_and_die "No input file was specified"
	fi

	# Conditional initialization.
	OUT=${OUT:="$IN"-unpacked}

	# Convert to absolute paths.
	IN=$(readlink -f "$IN")
	OUT=$(readlink -f "$OUT")
}

#
# Try to unpack the given file.
#
try_to_unpack()
{
	if [ $# -ne 2 ] || [ ! -s "$1" ] || [ -z "$2" ]; then
		echo "UNPACKER: wrong arguments" >&2
		return "$RET_NOTHING_TO_DO"
	fi

	local IN="$1"
	local OUT="$2"

	# Try to unpack via inhouse generic unpacker.
	# Create parameters.

	# Generic unpacker exit codes:
	# 0 Unpacker ended successfully.
	local UNPACKER_EXIT_CODE_OK=0
	# 1 There was not found matching plugin.
	local UNPACKER_EXIT_CODE_NOTHING_TO_DO=1
	# 2 At least one plugin failed at the unpacking of the file.
	local UNPACKER_EXIT_CODE_UNPACKING_FAILED=2
	# 3 Error with preprocessing of input file before unpacking.
	local UNPACKER_EXIT_CODE_PREPROCESSING_ERROR=3

	UNPACKER_PARAMS=(-d "$UNPACKER_PLUGINS_DIR")
	UNPACKER_PARAMS+=(-o "$OUT")
	UNPACKER_PARAMS+=("$IN")
	echo ""
	echo "##### Trying to unpack $IN into $OUT by using generic unpacker..."
	echo "RUN: $UNPACKER ${UNPACKER_PARAMS[@]}"
	$UNPACKER "${UNPACKER_PARAMS[@]}"
	UNPACKER_RETCODE="$?"
	if [ "$UNPACKER_RETCODE" = "$UNPACKER_EXIT_CODE_OK" ]; then
		echo "##### Unpacking by using generic unpacker: successfully unpacked"
		return "$RET_UNPACK_OK"
	elif [ "$UNPACKER_RETCODE" = "$UNPACKER_EXIT_CODE_NOTHING_TO_DO" ]; then
		echo "##### Unpacking by using generic unpacker: nothing to do"
		# Do not return -> try the next unpacker
	else
		# UNPACKER_EXIT_CODE_UNPACKING_FAILED
		# UNPACKER_EXIT_CODE_PREPROCESSING_ERROR
		echo "##### Unpacking by using generic unpacker: failed"
		# Do not return -> try the next unpacker
	fi

	# Try to unpack via UPX
	echo ""
	echo "##### Trying to unpack $IN into $OUT by using UPX..."
	echo "RUN: upx -d $IN -o $OUT"
	upx -d "$IN" -o "$OUT" >"$DEV_NULL"
	if [ "$?" = "0" ]; then
		echo "##### Unpacking by using UPX: successfully unpacked"
		if [ "$EXTENDED" = "yes" ]; then
			if [ "$UNPACKER_RETCODE" = "$UNPACKER_EXIT_CODE_NOTHING_TO_DO" ]; then
				return "$RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK"
			elif [ "$UNPACKER_RETCODE" -ge "$UNPACKER_EXIT_CODE_UNPACKING_FAILED" ]; then
				return "$RET_UNPACKER_FAILED_OTHERS_OK"
			fi
		else
			return "$RET_UNPACK_OK"
		fi
	else
		# We cannot distinguish whether upx failed or the input file was
		# not upx-packed
		echo "##### Unpacking by using UPX: nothing to do"
		# Do not return -> try the next unpacker
	fi

	# Return.
	if [ "$UNPACKER_RETCODE" -ge "$UNPACKER_EXIT_CODE_UNPACKING_FAILED" ]; then
		return "$RET_UNPACKER_FAILED"
	else
		return "$RET_NOTHING_TO_DO"
	fi
}

SCRIPT_NAME=$0
GETOPT_SHORTOPT="eho:"
GETOPT_LONGOPT="extended-exit-codes,help,output:"

# Check script arguments.
PARSED_OPTIONS=$(getopt -o "$GETOPT_SHORTOPT" -l "$GETOPT_LONGOPT" -n "$SCRIPT_NAME" -- "$@")

# Bad arguments.
[ $? -ne 0 ] && print_error_and_die "Getopt - parsing parameters failed"

eval set -- "$PARSED_OPTIONS"

while true; do
	case "$1" in
	-e|--extended-exit-codes)		# Use extented exit codes.
		[ "$EXTENDED" ] && print_error_and_die "Duplicate option: -e|--extended-exit-codes"
		EXTENDED="yes"
		shift;;
	-h|--help) 						# Help.
		print_help
		exit "$RET_UNPACK_OK";;
	-o|--output)					# Output file.
		[ "$OUT" ] && print_error_and_die "Duplicate option: -o|--output"
		OUT="$2"
		shift 2;;
	--)								# Input file.
		if [ $# -eq 2 ]; then
			IN="$2"
			[ ! -r "$IN" ] && print_error_and_die "The input file '$IN' does not exist or is not readable"
		elif [ $# -gt 2 ]; then		# Invalid options.
			print_error_and_die "Invalid options: '$2', '$3' ..."
		fi
		break;;
	esac
done

# Check arguments and set default values for unset options.
check_arguments

CONTINUE=1
FINAL_RC=-1
while [  "$CONTINUE" = "1" ]; do
	try_to_unpack "$IN" "$OUT.tmp"
	RC="$?"
	if [ "$RC" = "$RET_UNPACK_OK" ] || [ "$RC" = "$RET_UNPACKER_NOTHING_TO_DO_OTHERS_OK" ] || [ "$RC" = "$RET_UNPACKER_FAILED_OTHERS_OK" ]; then
		FINAL_RC="$RC"
		mv "$OUT.tmp" "$OUT"
		IN="$OUT"
	else
		# Remove the temporary file, just in case some of the unpackers crashed
		# during unpacking and left it on the disk (e.g. upx, see #1669).
		rm -f "$OUT.tmp"
		CONTINUE=0
	fi
done

if [ "$FINAL_RC" = "-1" ]; then
	exit "$RC"
else
	exit "$FINAL_RC"
fi
