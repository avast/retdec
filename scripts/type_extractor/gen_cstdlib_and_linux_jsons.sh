#!/usr/bin/env bash
#
# Generates 1 JSON for C standard library and 1 for other C header files in
# /usr/include.
#

# On macOS, we want the GNU version of 'readlink', which is available under
# 'greadlink':
gnureadlink()
{
	if hash greadlink 2> /dev/null; then
		greadlink "$@"
	else
		readlink "$@"
	fi
}

#
# C standard library headers.
#
CSTDLIB_HEADERS=(
	assert.h
	complex.h
	ctype.h
	errno.h
	fenv.h
	float.h
	inttypes.h
	iso646.h
	limits.h
	locale.h
	math.h
	setjmp.h
	signal.h
	stdalign.h
	stdarg.h
	stdatomic.h
	stdbool.h
	stddef.h
	stdint.h
	stdio.h
	stdlib.h
	stdnoreturn.h
	string.h
	tgmath.h
	threads.h
	time.h
	uchar.h
	wchar.h
	wctype.h
)

#
# Files we don't want in JSONs.
#
FILES_PATTERNS_TO_FILTER_OUT=(
	GL/
	Qt.*/
	SDL.*/
	X11/
	alsa/
	c\\+\\+/
	dbus.*/
	glib.*/
	libdrm/
	libxml2/
	llvm.*/
	mirclient/
    php[0-9.-]*/
	pulse/
	python.*/
	ruby.*/
	wayland.*/
	xcb/
)

SEP='\|'
FILES_FILTER=$(printf "$SEP%s" "${FILES_PATTERNS_TO_FILTER_OUT[@]}")
FILES_FILTER=${FILES_FILTER:${#SEP}}

#
# Paths.
#
SCRIPT_DIR="$(dirname "$(gnureadlink -e "$0")")"
SCRIPT_NAME="$(basename "$SCRIPT_NAME")"
EXTRACTOR="$SCRIPT_DIR/extract_types.py"
MERGER="$SCRIPT_DIR/merge_jsons.py"

INCLUDE_DIR="/usr/include/"

OUT_DIR="."
STD_LIB_OUT_DIR="$OUT_DIR/gen_tmp_cstdlib"
STD_LIB_JSON="$OUT_DIR/cstdlib.json"
LINUX_OUT_DIR="$OUT_DIR/gen_tmp_linux"
LINUX_JSON="$OUT_DIR/linux.json"
CSTDLIB_PRIORITY_OUT_DIR="$OUT_DIR/gen_tmp_cstdlib_priority"
LINUX_PRIORITY_OUT_DIR="$OUT_DIR/gen_tmp_linux_priority"

#
# Print help.
#
print_help()
{
	echo "Generator of JSON files containing C-types information for C standard library"
	echo "and other header files in /usr/include/ directory."
	echo ""
	echo "Usage:"
	echo "    $SCRIPT_NAME [OPTIONS]"
	echo ""
	echo "Options:"
	echo "    -f    --files-filter       Pattern to ignore specific header files."
	echo "    -h,   --help               Print this help message."
	echo "    -i    --json-indent N      Set indentation in JSON files. Default 1"
	echo "    -N    --no-cleanup         Do not remove dirs with JSONs for individual header files."
	echo "          --cstdlib-headers    Set path to the C standard library headers with high-priority types info."
	echo "          --linux-headers      Set path to the Linux headers with high-priority types info."
}

#
# Prints the given error message ($1) to stderr and exits.
#
print_error_and_die()
{
	echo "Error: $1" >&2
	exit 1
}

#
# Parse and check script arguments.
#
GETOPT_SHORTOPT="f:hi:Np:"
GETOPT_LONGOPT="cstdlib-headers:,files-filter:,help,json-indent:,linux-headers:,no-cleanup"
PARSED_OPTIONS=$(getopt -o "$GETOPT_SHORTOPT" -l "$GETOPT_LONGOPT" -n "$SCRIPT_NAME" -- "$@")
if [ $? -ne 0 ]; then
	print_error_and_die "Failed to parse parameters via getopt"
fi

eval set -- "$PARSED_OPTIONS"
while true; do
	case "$1" in
	-f|--files-filter)
		FILES_FILTER="$FILES_FILTER\|$2"
		shift 2;;
	-i|--json-indent)
		[ "$JSON_INDENT" ] && print_error_and_die "Duplicate option: -i|--json-indent"
		JSON_INDENT="$2"
		shift 2;;
	-h|--help)
		print_help
		exit 0;;
	-N|--no-cleanup)
		[ "$CLEANUP" ] && print_error_and_die "Duplicate option: -N|--no-cleanup"
		CLEANUP="no"
		shift;;
	--cstdlib-headers)
		[ "$CSTDLIB_PRIORITY_PATH" ] && print_error_and_die "Duplicate option: --cstdlib-headers"
		[ -d "$2" ] || print_error_and_die "Unknown directory: $2"
		CSTDLIB_PRIORITY_PATH="$2"
		shift 2;;
	--linux-headers)
		[ "$LINUX_PRIORITY_PATH" ] && print_error_and_die "Duplicate option: --linux-headers"
		[ -d "$2" ] || print_error_and_die "Unknown directory: $2"
		LINUX_PRIORITY_PATH="$2"
		shift 2;;
	--)
		if [ $# -ne 1 ]; then
			print_error_and_die "Unrecognized parameter '$2'"
			exit 1
		fi
		break;;
	esac
done

JSON_INDENT=${JSON_INDENT:=1}
CLEANUP=${CLEANUP:=yes}

#
# Initial cleanup.
#
rm -rf "$STD_LIB_OUT_DIR"
mkdir "$STD_LIB_OUT_DIR"

rm -rf "$LINUX_OUT_DIR"
mkdir "$LINUX_OUT_DIR"

rm -rf "$CSTDLIB_PRIORITY_OUT_DIR"
mkdir "$CSTDLIB_PRIORITY_OUT_DIR"

rm -rf "$LINUX_PRIORITY_OUT_DIR"
mkdir "$LINUX_PRIORITY_OUT_DIR"

#
# Generate JSONs for whole /usr/include path.
# Filter out unwanted headers.
# Move standard headers to other dir.
#
$EXTRACTOR "$INCLUDE_DIR" -o "$LINUX_OUT_DIR"

FILES_FILTER=${FILES_FILTER//\//_}
find "$LINUX_OUT_DIR/" -regex "$LINUX_OUT_DIR/.*\($FILES_FILTER\).*" -delete

#
# Move standard library headers to other directory.
# Edit standard header paths to look like type-extractor generated jsons.
#
for header in "${CSTDLIB_HEADERS[@]}"; do
    for f in $(find "$INCLUDE_DIR" -name "$header"); do
        f=${f#$INCLUDE_DIR}
        f=${f////_}
        f=${f/%\.h/.json}
        if [ -f "$LINUX_OUT_DIR/$f" ]; then
            mv "$LINUX_OUT_DIR/$f" "$STD_LIB_OUT_DIR"
        fi
    done
done

#
# Extract types info from high-priority cstdlib and linux headers if paths were given.
#
if [ -n "$CSTDLIB_PRIORITY_PATH" ]; then
	$EXTRACTOR "$CSTDLIB_PRIORITY_PATH" -o "$CSTDLIB_PRIORITY_OUT_DIR"
fi

if [ -n "$LINUX_PRIORITY_PATH" ]; then
	$EXTRACTOR "$LINUX_PRIORITY_PATH" -o "$LINUX_PRIORITY_OUT_DIR"
fi

#
# Merging.
# Priority headers must be first.
# Cstdlib priority headers are merged to the C standard library JSON,
# Linux priority headers to the Linux JSON.
#
$MERGER "$CSTDLIB_PRIORITY_OUT_DIR" "$STD_LIB_OUT_DIR" -o "$STD_LIB_JSON" --json-indent "$JSON_INDENT"
$MERGER "$LINUX_PRIORITY_OUT_DIR" "$LINUX_OUT_DIR" -o "$LINUX_JSON" --json-indent "$JSON_INDENT"

#
# Optional cleanup at the end.
#
if [ "$CLEANUP" = "yes" ]; then
	rm -rf "$STD_LIB_OUT_DIR"
	rm -rf "$LINUX_OUT_DIR"
	rm -rf "$PRIORITY_HEADERS_OUT_DIR"
	rm -rf "$CSTDLIB_PRIORITY_OUT_DIR"
	rm -rf "$LINUX_PRIORITY_OUT_DIR"
fi
