#!/bin/bash
#
# Runs decompile.sh with the given arguments over all executable files in the
# given directory and subdirectories.
#
# Requirements:
#  - bash
#  - the `find` and `timeout` commands
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_UTILS" ]; then
	DECOMPILER_UTILS="$SCRIPTPATH/utils.sh"
fi

. "$DECOMPILER_UTILS"

##
## Check that all script requirements are satisfied.
##
for cmd in "find" "timeout"; do
	command -v $cmd > /dev/null 2>&1 || {
		echo "error: The \`$cmd\` command is required but it is not" \
			"available. Aborting." >&2
		exit 1
	}
done

##
## Configuration.
##
# Timeout for the decompile.sh script (in seconds).
TIMEOUT=300
# Column in which the status messages ([OK] etc.) are emitted.
STATUS_COLUMN=80

##
## Prints help to stream $1.
##
print_help() {
	echo "Runs decompile.sh with the given optional arguments (ARGS) over all" > $1
	echo "executable files in the given directory (PATH) and subdirectories." > $1
	echo "" > $1
	echo "Usage:" > $1
	echo "    $0 PATH [ARGS]" > $1
	echo "" > $1
}

##
## Parse script arguments.
##
if [ -z $1 ]; then
	print_help /dev/stderr
	exit 1
elif [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
	print_help /dev/stdout
	exit 0
fi
SEARCHED_PATH="$1"
DECOMPILE_SH_ARGS="${@:2}"

# To provide a more readable output, make sure that the path ends with '/'.
SEARCHED_PATH="${SEARCHED_PATH%/}/"

##
## Find all binary executable files in the requested path and store them in an
## array.
##
# Notes:
# - Since there may be spaces or new lines in the file names, we use the NULL
#   byte as the separator.
# - Skip *-unpacked files (these are our files, unpacked with UPX).
# - The following loop is based on http://mywiki.wooledge.org/BashFAQ/020.
echo "Searching for executable files in $SEARCHED_PATH..." >&2
unset FILES i
while IFS= read -r -d $'\0' file; do
	FILES[i++]="$file"
	echo -ne "  -- Found ${#FILES[@]} files.\r" >&2
done < <(find "$SEARCHED_PATH" -type f -exec bash -c '
	if [[ "$1" =~ .*-unpacked ]]; then
		exit 1
	elif [[ "$(file "$1")" =~ .*executable.* ]]; then
		exit 0
	fi
	exit 1
' bash {} \; -print0)
echo -ne "\n\n" >&2

##
## We need at least one file.
##
num_of_files=${#FILES[@]}
if [ $num_of_files == 0 ]; then
	echo "error: No files found. Aborting." >&2
	exit 1
fi

##
## Run decompile.sh over all the found files.
##
echo -n "Running \`decompile-sh"
if [ "$DECOMPILE_SH_ARGS" != "" ]; then
	echo -n "$DECOMPILE_SH_ARGS"
fi
echo "\` over $num_of_files files with timeout ${TIMEOUT}s" \
	"(run \`kill $$\` to terminate this script)..." >&2
echo "" >&2
for i in "${!FILES[@]}"; do
	# i/max
	file_num=`expr $i + 1`
	echo -ne "$file_num/$num_of_files"
	max_column=`expr length "$num_of_files/$num_of_files"`
	curr_column=`expr length "$file_num/$num_of_files"`
	num_of_spaces=`expr $max_column - $curr_column + 4`
	printf "%${num_of_spaces}s"

	# file
	file="${FILES[$i]}"
	file_short="${file#$SEARCHED_PATH}"
	echo -n "$file_short"
	file_name_length=`expr length "${file#$SEARCHED_PATH}"`
	if [ $file_name_length -lt $STATUS_COLUMN ]; then
		num_of_spaces=`expr $STATUS_COLUMN - $file_name_length`
		printf "%${num_of_spaces}s"
	else
		echo -n " "
	fi

	# decompile.sh
	log_file="$file.log.verbose"
	timeout $TIMEOUT $DECOMPILE_SH -m bin $DECOMPILE_SH_ARGS "$file" > "$log_file" 2>&1
	rc=$?

	# status
	case $rc in
		0)   echo "[OK]" ;;
		124) echo "[TIMEOUT]" ;;
		*)   echo "[FAIL]" ;;
	esac
done

# Success!
exit 0
