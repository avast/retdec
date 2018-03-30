#!/usr/bin/env bash
#
# Generates JSON files from includes in Windows SDK and Windows Drivers Kit.
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
# Paths.
#
SCRIPT_DIR="$(dirname "$(gnureadlink -e "$0")")"
SCRIPT_NAME="$(basename "$SCRIPT_NAME")"
EXTRACTOR="$SCRIPT_DIR/extract_types.py"
MERGER="$SCRIPT_DIR/merge_jsons.py"

OUT_DIR="."

#
# Windows SDK paths.
#
WIN_UCRT_OUT_DIR="$OUT_DIR/windows_ucrt"
WIN_SHARED_OUT_DIR="$OUT_DIR/windows_shared"
WIN_UM_OUT_DIR="$OUT_DIR/windows_um"
WIN_WINRT_OUT_DIR="$OUT_DIR/windows_winrt"
WIN_NETFX_OUT_DIR="$OUT_DIR/windows_netfx"
WIN_OUT_JSON="$OUT_DIR/windows.json"
WIN_OUT_JSON_WITH_UNUSED_TYPES="$OUT_DIR/windows_all_types.json"

#
# Windows Drivers Kit paths.
#
WDK_KM_OUT_DIR="$OUT_DIR/windrivers_km"
WDK_MMOS_OUT_DIR="$OUT_DIR/windrivers_mmos"
WDK_SHARED_OUT_DIR="$OUT_DIR/windrivers_shared"
WDK_UM_OUT_DIR="$OUT_DIR/windrivers_um"
WDK_KMDF_OUT_DIR="$OUT_DIR/windrivers_kmdf"
WDK_UMDF_OUT_DIR="$OUT_DIR/windrivers_umdf"
WDK_OUT_JSON="$OUT_DIR/windrivers.json"

#
# Prints help.
#
print_help()
{
	echo "Generates JSON files from includes in Windows SDK and Windows Drivers Kit."
	echo ""
	echo "Usage:"
	echo "    $SCRIPT_NAME [OPTIONS] --sdk WIN_SDK_DIR --wdk WDK_DIR"
	echo ""
	echo "Options:"
	echo "    -h,   --help               Print this help message."
	echo "    -i    --json-indent N      Set indentation in JSON files. Default 1"
	echo "    -N    --no-cleanup         Do not remove dirs with JSONs for individual header files."
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
# Removes temporary dirs and files used to generate JSONS that are merged later.
#
remove_tmp_dirs_and_files()
{
	rm -rf "$WIN_UCRT_OUT_DIR"
	rm -rf "$WIN_SHARED_OUT_DIR"
	rm -rf "$WIN_UM_OUT_DIR"
	rm -rf "$WIN_WINRT_OUT_DIR"
	rm -rf "$WIN_NETFX_OUT_DIR"
    rm -f "$WIN_OUT_JSON_WITH_UNUSED_TYPES"

    rm -rf "$WDK_KM_OUT_DIR"
	rm -rf "$WDK_MMOS_OUT_DIR"
	rm -rf "$WDK_SHARED_OUT_DIR"
	rm -rf "$WDK_UM_OUT_DIR"
	rm -rf "$WDK_KMDF_OUT_DIR"
	rm -rf "$WDK_UMDF_OUT_DIR"
}

#
# Parse and check script arguments.
#
GETOPT_SHORTOPT="hi:N"
GETOPT_LONGOPT="help,json-indent:,no-cleanup,sdk:,wdk:"
PARSED_OPTIONS=$(getopt -o "$GETOPT_SHORTOPT" -l "$GETOPT_LONGOPT" -n "$SCRIPT_NAME" -- "$@")
if [ $? -ne 0 ]; then
	print_error_and_die "Failed to parse parameters via getopt"
fi

eval set -- "$PARSED_OPTIONS"
while true; do
	case "$1" in
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
	--sdk)
        WIN_SDK_DIR="$2"
        if [ ! -r "$WIN_SDK_DIR" ]; then
            print_error_and_die "$WIN_SDK_DIR: No such file or directory"
        fi
        shift 2;;
	--wdk)
        WDK_DIR="$2"
        if [ ! -r "$WDK_DIR" ]; then
            print_error_and_die "$WDK_DIR: No such file or directory"
        fi
        shift 2;;
    --)
		if [ $# -ne 1 ]; then
			print_error_and_die "Invalid options: '$2'"
			exit 1
		fi
		break;;
	esac
done

CLEANUP=${CLEANUP:=yes}
JSON_INDENT=${JSON_INDENT:=1}

# Path to the Windows SDK directory is required.
if [ -z "$WIN_SDK_DIR" ] || [ -z "$WDK_DIR" ]; then
	print_help
	exit 1
fi

WIN_UCRT_IN_DIR="$WIN_SDK_DIR/10/Include/10.0.10150.0/ucrt"
WIN_SHARED_IN_DIR="$WIN_SDK_DIR/10/Include/10.0.10240.0/shared"
WIN_UM_IN_DIR="$WIN_SDK_DIR/10/Include/10.0.10240.0/um"
WIN_WINRT_IN_DIR="$WIN_SDK_DIR/10/Include/10.0.10240.0/winrt"
WIN_NETFX_IN_DIR="$WIN_SDK_DIR/NETFXSDK/4.6/Include/um"

WDK_KM_IN_DIR="$WDK_DIR/10.0.10586.0/km"
WDK_MMOS_IN_DIR="$WDK_DIR/10.0.10586.0/mmos"
WDK_SHARED_IN_DIR="$WDK_DIR/10.0.10586.0/shared"
WDK_UM_IN_DIR="$WDK_DIR/10.0.10586.0/um"
WDK_KMDF_IN_DIR="$WDK_DIR/wdf/kmdf"
WDK_UMDF_IN_DIR="$WDK_DIR/wdf/umdf"

#
# Initial cleanup.
#
remove_tmp_dirs_and_files
mkdir -p "$WIN_UCRT_OUT_DIR"
mkdir -p "$WIN_SHARED_OUT_DIR"
mkdir -p "$WIN_UM_OUT_DIR"
mkdir -p "$WIN_WINRT_OUT_DIR"
mkdir -p "$WIN_NETFX_OUT_DIR"

mkdir -p "$WDK_KM_OUT_DIR"
mkdir -p "$WDK_MMOS_OUT_DIR"
mkdir -p "$WDK_SHARED_OUT_DIR"
mkdir -p "$WDK_UM_OUT_DIR"
mkdir -p "$WDK_KMDF_OUT_DIR"
mkdir -p "$WDK_UMDF_OUT_DIR"

#
# Parse the includes in the given Windows SDK directory and merge the generated
# JSON files.
#
$EXTRACTOR "$WIN_UCRT_IN_DIR" -o "$WIN_UCRT_OUT_DIR"

$EXTRACTOR "$WIN_SHARED_IN_DIR" -o "$WIN_SHARED_OUT_DIR"

$EXTRACTOR "$WIN_UM_IN_DIR" -o "$WIN_UM_OUT_DIR"

$EXTRACTOR "$WIN_WINRT_IN_DIR" -o "$WIN_WINRT_OUT_DIR"

$EXTRACTOR "$WIN_NETFX_IN_DIR" -o "$WIN_NETFX_OUT_DIR"

$MERGER "$WIN_SHARED_OUT_DIR" "$WIN_UM_OUT_DIR" "$WIN_UCRT_OUT_DIR" "$WIN_WINRT_OUT_DIR" "$WIN_NETFX_OUT_DIR" -o "$WIN_OUT_JSON" --json-indent "$JSON_INDENT"

#
# Parse the includes in the given WDK directory and merge the generated
# JSON files.
#
$EXTRACTOR "$WDK_KM_IN_DIR" -o "$WDK_KM_OUT_DIR"

$EXTRACTOR "$WDK_MMOS_IN_DIR" -o "$WDK_MMOS_OUT_DIR"

$EXTRACTOR "$WDK_SHARED_IN_DIR" -o "$WDK_SHARED_OUT_DIR"

$EXTRACTOR "$WDK_UM_IN_DIR" -o "$WDK_UM_OUT_DIR"

for dir in $(ls $WDK_KMDF_IN_DIR); do
    $EXTRACTOR "$WDK_KMDF_IN_DIR/$dir" -o "$WDK_KMDF_OUT_DIR"
done

for dir in $(ls $WDK_UMDF_IN_DIR); do
    $EXTRACTOR "$WDK_UMDF_IN_DIR/$dir" -o "$WDK_UMDF_OUT_DIR"
done

$MERGER "$WDK_SHARED_OUT_DIR" "$WDK_UM_OUT_DIR" "$WDK_KM_OUT_DIR" "$WDK_MMOS_OUT_DIR" "$WDK_KMDF_OUT_DIR" "$WDK_UMDF_OUT_DIR" -o "$WDK_OUT_JSON" --json-indent "$JSON_INDENT"

#
# WDK uses many types defined in Windows SDK. We need SDK JSON with all types extracted
# and merge it with WDK. SDK functions must be removed!
#
$MERGER "$WIN_SHARED_OUT_DIR" "$WIN_UM_OUT_DIR" "$WIN_UCRT_OUT_DIR" "$WIN_WINRT_OUT_DIR" "$WIN_NETFX_OUT_DIR" -o "$WIN_OUT_JSON_WITH_UNUSED_TYPES" --json-indent "$JSON_INDENT" --keep-unused-types

if [ "$JSON_INDENT" -eq 0 ]; then
    sed -i -e "s/^.*\}, \"types\": \{/\{\"functions\": \{\}, \"types\": \{/" "$WIN_OUT_JSON_WITH_UNUSED_TYPES"
else
    TYPES_LINE_NUMBER=$(egrep -n "^\s*\"types\": \{" "$WIN_OUT_JSON_WITH_UNUSED_TYPES" | cut -f1 -d:)
    TYPES_LINE_NUMBER=$(($TYPES_LINE_NUMBER - 1))
    sed -i -e "1,$TYPES_LINE_NUMBER d" "$WIN_OUT_JSON_WITH_UNUSED_TYPES"
    sed -i -e "1s/^/\{\"functions\": \{\},\n/" "$WIN_OUT_JSON_WITH_UNUSED_TYPES"
fi

$MERGER "$WDK_OUT_JSON" "$WIN_OUT_JSON_WITH_UNUSED_TYPES" -o "$WDK_OUT_JSON" --json-indent $JSON_INDENT

#
# Optional cleanup at the end.
#
if [ "$CLEANUP" = "yes" ]; then
    remove_tmp_dirs_and_files
fi
