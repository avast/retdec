#!/bin/bash
#
# Runs decompile.sh with the given arguments over all files in the
# given static library.
#
# Requirements:
#  - bash
#  - the `timeout` command
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_UTILS" ]; then
	DECOMPILER_UTILS="$SCRIPTPATH/utils.sh"
fi

. "$DECOMPILER_UTILS"

##
## Check that all script requirements are satisfied.
##
for CMD in "timeout"; do
	command -v $CMD > /dev/null 2>&1 || {
		echo "error: The \`$CMD\` command is required but it is not" \
			"available. Aborting." >&2
		exit 1
	}
done

##
## Configuration.
##
TIMEOUT=300 # Timeout for decompile.sh script.

##
## Prints help to stream $1.
##
print_help() {
	echo "Runs decompile.sh with the given optional arguments over all files" > "$1"
	echo "in the given static library or prints list of files in plain text" > "$1"
	echo "with --plain argument or in JSON format with --json argument. You" > "$1"
	echo "can pass arguments for decompilation after double-dash '--' argument." > "$1"
	echo "" > "$1"
	echo "Usage:" > "$1"
	echo "    $0 ARCHIVE [-- ARGS]" > "$1"
	echo "    $0 ARCHIVE --plain|--json" > "$1"
	echo "" > "$1"
}

##
## Prints error in either plain text or JSON format.
## One argument required: error message.
##
print_error_plain_or_json() {
	if [ "$JSON_FORMAT" ]; then
		M=$(echo "$1" | sed 's,\\,\\\\,g')
		M=$(echo "$M" | sed 's,\",\\",g')
		echo "{"
		echo "    \"error\" : \"$M\""
		echo "}"
		exit 1
	else
		# Otherwise print in plain text.
		print_error_and_die "$1"
	fi
}

##
## Cleans up all temporary files.
## No arguments accepted.
##
cleanup() {
	rm -f "$TMP_ARCHIVE"
}

##
## Parse script arguments.
##
while [[ $# -gt 0 ]]
do
	case $1 in
		-h|--help)
			print_help /dev/stdout
			exit 0;;
		--list)
			LIST_MODE=1
			shift;;
		--plain)
			[ "$JSON_FORMAT" ] && print_error_and_die "Arguments --plain and --json are mutually exclusive."
			LIST_MODE=1
			PLAIN_FORMAT=1
			shift;;
		--json)
			[ "$PLAIN_FORMAT" ] && print_error_and_die "Arguments --plain and --json are mutually exclusive."
			LIST_MODE=1
			JSON_FORMAT=1
			shift;;
		--)
			# Skip -- and store arguments for decompilation.
			shift
			DECOMPILE_SH_ARGS=$*
			break;;
		*)
			! [ -f "$1" ] && print_error_and_die "Input '$1' is not a valid file."
			LIBRARY_PATH="$1"
			shift;;
	esac
done

# Check arguments
[ ! "$LIBRARY_PATH" ] && print_error_plain_or_json "No input file."

# Check for archives packed in Mach-O Universal Binaries.
if is_macho_archive "$LIBRARY_PATH"; then
	if [ "$LIST_MODE" ]; then
		if [ "$JSON_FORMAT" ]; then
			"$EXTRACT" --objects --json "$LIBRARY_PATH"
		else
			# Otherwise print in plain text.
			"$EXTRACT" --objects "$LIBRARY_PATH"
		fi

		# Not sure why failure is used there.
		exit 1
	fi

	TMP_ARCHIVE="$LIBRARY_PATH.a"
	"$EXTRACT" --best --out "$TMP_ARCHIVE" "$LIBRARY_PATH"
	LIBRARY_PATH="$TMP_ARCHIVE"
fi

# Check for thin archives.
if has_thin_archive_signature "$LIBRARY_PATH"; then
	print_error_plain_or_json "File is a thin archive and cannot be decompiled."
fi

# Check if file is archive
if ! is_valid_archive "$LIBRARY_PATH"; then
	print_error_plain_or_json "File is not supported archive or is not readable."
fi

# Check number of files.
FILE_COUNT=$(archive_object_count "$LIBRARY_PATH")
if [ "$FILE_COUNT" -le 0 ]; then
	print_error_plain_or_json "No files found in archive."
fi

##
## List only mode.
##
if [ "$LIST_MODE" ]; then
	if [ "$JSON_FORMAT" ]; then
		archive_list_numbered_content_json "$LIBRARY_PATH"
	else
		# Otherwise print in plain text.
		archive_list_numbered_content "$LIBRARY_PATH"
	fi

	cleanup
	exit 0
fi

##
## Run decompile.sh over all the found files.
##
echo -n "Running \`decompile-sh"
if [ "$DECOMPILE_SH_ARGS" != "" ]; then
	echo -n "$DECOMPILE_SH_ARGS"
fi
echo "\` over $FILE_COUNT files with timeout ${TIMEOUT}s" \
	"(run \`kill $$\` to terminate this script)..." >&2
echo "" >&2
for ((INDEX=0; INDEX<FILE_COUNT; INDEX++)); do
	FILE_INDEX=$((INDEX + 1))
	echo -ne "$FILE_INDEX/$FILE_COUNT\t\t"

	# We have to use indexes instead of names because archives can contain multiple files with same name.
	LOG_FILE="$LIBRARY_PATH.file_$FILE_INDEX.log.verbose"                                                    # Do not escape!
	timeout $TIMEOUT "$DECOMPILE_SH" --ar-index="$INDEX" -o "$LIBRARY_PATH.file_$FILE_INDEX" "$LIBRARY_PATH" $DECOMPILE_SH_ARGS > "$LOG_FILE" 2>&1
	RC=$?

	# Print status.
	case $RC in
		0)   echo "[OK]" ;;
		124) echo "[TIMEOUT]" ;;
		*)   echo "[FAIL]" ;;
	esac
done

# Cleanup
cleanup

# Success!
exit 0
