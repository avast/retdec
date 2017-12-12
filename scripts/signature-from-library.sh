#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_UTILS" ]; then
	DECOMPILER_UTILS="$SCRIPTPATH/utils.sh"
fi

. "$DECOMPILER_UTILS"

##
## Prints help to stream $1.
##
print_help() {
	echo -e "Create Yara rules file from static libraries." > "$1"
	echo -e "Usage: signature-from-library.sh [OPTIONS] -o OUTPUT INPUT_1 [... INPUT_N]\n" > "$1"
	echo "Options:" > "$1"
	echo "    -n --no-cleanup" > "$1"
	echo "        Temporary .pat files will be kept." > "$1"
	echo "" > "$1"
	echo "    -o --output path" > "$1"
	echo "        Where result(s) will be stored." > "$1"
	echo "" > "$1"
	echo "    -m --min-pure unsigned" > "$1"
	echo "        Minimum pure information needed for patterns (default 16)." > "$1"
	echo "" > "$1"
	echo "    -i --ignore-nops opcode" > "$1"
	echo "        Ignore trailing NOPs when computing (pure) size." > "$1"
	echo "" > "$1"
	echo "    -l --logfile" > "$1"
	echo "        Add log-file with '.log' suffix from pat2yara." > "$1"
	echo "" > "$1"
	echo "    -b --bin2pat-only" > "$1"
	echo "        Stop after bin2pat." > "$1"
	echo "" > "$1"
}

##
## Exit with error message $1 and clean up temporary files.
##
die_with_error_and_cleanup() {
	# Cleanup.
	[ ! "$NO_CLEANUP" ] && temporary_files_cleanup
	print_error_and_die "$1."
}

##
## Removes temporary files.
##
temporary_files_cleanup() {
	rm -r "$DIR_PATH"
}

# Parse arguments.
while [[ $# -gt 0 ]]
do
	case $1 in
		-h|--help)
			print_help /dev/stdout
			exit 0;;
		-n|--no-cleanup)
			NO_CLEANUP=1
			shift;;
		-l|--logfile)
			DO_LOGFILE=1
			shift;;
		-b|--bin2pat-only)
			BIN2PAT_ONLY=1
			shift;;
		-m|--min-pure)
			[ "$MIN_PURE" ] && die_with_error_and_cleanup "duplicate option: --min-pure"
			MIN_PURE=$2
			shift 2;;
		-i|--ignore-nops)
			[ "$IGNORE_NOP" ] && die_with_error_and_cleanup "duplicate option: --ignore-nops"
			IGNORE_NOP="--ignore-nops"
			IGNORE_OPCODE=$2
			shift 2;;
		-o|--output)
			[ "$OUT_PATH" ] && die_with_error_and_cleanup "duplicate option: --output"
			OUT_PATH=$2
			shift 2;;
		*)
			! [ -f "$1" ] && die_with_error_and_cleanup "input '$1' is not a valid file nor argument"
			INPUT_LIBS+=("$1")
			shift;;
	esac
done

# Check inputs.
if [ "${#INPUT_LIBS[@]}" -lt 1 ]; then
	die_with_error_and_cleanup "no input files"
fi

# Output directory - compulsory argument.
if [ -z "$OUT_PATH" ]; then
	die_with_error_and_cleanup "option -o|--output is compulsory"
else
	FILE_PATH="$OUT_PATH"
	DIR="$(dirname "$(readlink -f "$FILE_PATH")")"
	DIR_PATH=$(mktemp -d "$DIR/XXXXXXXXX")
fi

# Set default --min-pure information argument.
if ! [ "$MIN_PURE" ]; then
	MIN_PURE="16"
fi

# Create .pat files for every library.
for LIB_PATH in "${INPUT_LIBS[@]}"; do
	# Check for invalid archives.
	if ! is_valid_archive "$LIB_PATH"; then
		echo "ignoring file '$LIB_PATH' - not valid archive"
		continue
	fi

	# Get library name for .pat file.
	LIB_NAME_TMP="$(basename "$LIB_PATH")"
	LIB_NAME="${LIB_NAME_TMP%%.*}"

	# Create sub-directory for object files.
	OBJECT_DIRECTORY="$DIR_PATH/$LIB_NAME-objects"
	OBJECT_DIRECTORIES+=("$OBJECT_DIRECTORY")
	mkdir "$OBJECT_DIRECTORY"

	# Extract all files to temporary folder.
	"$AR" "$LIB_PATH" --extract --output "$OBJECT_DIRECTORY"

	# List all extracted objects.
	IFS_OLD="$IFS"
	IFS=$'\n'
	OBJECTS=($(find "$OBJECT_DIRECTORY" -type f))
	IFS="$IFS_OLD"

	# Extract patterns from library.
	PATTERN_FILE="$DIR_PATH/$LIB_NAME.pat"
	PATTERN_FILES+=("$PATTERN_FILE")
	"$BIN2PAT" -o "$PATTERN_FILE" "${OBJECTS[@]}"
	[ "$?" -ne "0" ] && die_with_error_and_cleanup "utility bin2pat failed when processing '$LIB_PATH'"

	# Remove extracted objects continuously.
	[ ! "$NO_CLEANUP" ] && rm -r "$OBJECT_DIRECTORY"
done

# Skip second step - only .pat files will be created.
if [ "$BIN2PAT_ONLY" ]; then
	[ ! "$NO_CLEANUP" ] && rm -f "${OBJECT_DIRECTORIES[@]}"
	exit 0
fi

# Create final .yara file from .pat files.
if [ "$DO_LOGFILE" ]; then
	"$PAT2YARA" "${PATTERN_FILES[@]}" --min-pure $MIN_PURE -o "$FILE_PATH" -l "$FILE_PATH.log" $IGNORE_NOP $IGNORE_OPCODE
	[ "$?" -ne "0" ] && die_with_error_and_cleanup "utility pat2yara failed"
else
	"$PAT2YARA" "${PATTERN_FILES[@]}" --min-pure $MIN_PURE -o "$FILE_PATH" $IGNORE_NOP $IGNORE_OPCODE
	[ "$?" -ne "0" ] && die_with_error_and_cleanup "utility pat2yara failed"
fi

# Do cleanup.
[ ! "$NO_CLEANUP" ] && temporary_files_cleanup
