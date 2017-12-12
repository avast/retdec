#!/bin/bash
#
# A wrapper for fileinfo that:
#
#  - uses also external YARA patterns,
#  - is able to analyze archives (.a/.lib files).
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_UTILS" ]; then
	DECOMPILER_UTILS="$SCRIPTPATH/utils.sh"
fi

. "$DECOMPILER_UTILS"

# When analyzing an archive, use `decompile-archive.sh --list` instead of
# `fileinfo` because fileinfo is currently unable to analyze archives.
#
# First, we have to find path to the input file. We take the first parameter
# that does not start with a dash. This is a simplification and may not work in
# all cases. A proper solution would need to parse fileinfo parameters, which
# would be complex.
for	arg in "$@"; do
	if [ "${arg:0:1}" != "-" ]; then
		IN="$arg"
		if ! has_archive_signature "$IN"; then
			# The input file is not an archive.
			break
		fi

		# The input file is an archive, so use decompile-archive.sh instead of
		# fileinfo.
		DECOMPILE_ARCHIVE_SH_PARAMS=("$IN" --list)
		# When a JSON output was requested (any of the parameters is
		# -j/--json), forward it to decompile-archive.sh.
		for	arg in "$@"; do
			if [ "$arg" = "-j" ] || [ "$arg" = "--json" ]; then
				DECOMPILE_ARCHIVE_SH_PARAMS+=(--json)
			fi
		done
		$DECOMPILE_ARCHIVE_SH "${DECOMPILE_ARCHIVE_SH_PARAMS[@]}"
		exit $?
	fi
done

# We are not analyzing an archive, so proceed to fileinfo.
FILEINFO_PARAMS=()

for par in "${FILEINFO_EXTERNAL_YARA_PRIMARY_CRYPTO_DATABASES[@]}"; do
	FILEINFO_PARAMS+=(--crypto "$par")
done

for var in "$@"; do
	if [ "$var" = "--use-external-patterns" ]; then
		for par in "${FILEINFO_EXTERNAL_YARA_EXTRA_CRYPTO_DATABASES[@]}"; do
			FILEINFO_PARAMS+=(--crypto "$par")
		done
	else
		FILEINFO_PARAMS+=("$var")
	fi
done

$FILEINFO "${FILEINFO_PARAMS[@]}"
