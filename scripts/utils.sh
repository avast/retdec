#!/bin/bash
#
# Compilation and decompilation utility functions.
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_CONFIG" ]; then
	DECOMPILER_CONFIG="$SCRIPTPATH/config.sh"
fi

. "$DECOMPILER_CONFIG"

#
# Print error message to stderr and die.
# 1 argument is needed
# Returns - 1 if number of arguments is incorrect
#
print_error_and_die()
{
	if [ "$#" != "1" ]; then
		exit 1
	fi
	echo "Error: $1" >&2
	exit 1
}

#
# Print warning message to stderr.
# 1 argument is needed
# Returns - 1 if number of arguments is incorrect
#
print_warning()
{
	if [ "$#" != "1" ]; then
		return 1
	fi
	echo "Warning: $1" >&2
	return 0
}

#
# Check if file has any ar signature.
# 1 argument is needed - file path
# Returns - 0 if file has ar signature
#           1 if number of arguments is incorrect
#           2 no signature
#
has_archive_signature()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$AR" "$1" --arch-magic && return 0
	return 2
}

#
# Check if file has thin ar signature.
# 1 argument is needed - file path
# Returns - 0 if file has thin ar signature
#           1 if number of arguments is incorrect
#           2 no signature
#
has_thin_archive_signature()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$AR" "$1" --thin-magic && return 0
	return 2
}

#
# Check if file is an archive we can work with.
# 1 argument is needed - file path
# Returns - 0 if file is valid archive
#           1 if file is invalid archive
#
is_valid_archive()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	# We use our own messages so throw original output away.
	"$AR" "$1" --valid &> "$DEV_NULL"
}

#
# Counts object files in archive.
# 1 argument is needed - file path
# Returns - 1 if error occurred
#
archive_object_count()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$AR" "$1" --object-count
}

#
# Print content of archive.
# 1 argument is needed - file path
# Returns - 1 if number of arguments is incorrect
#
archive_list_content()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$AR" "$1" --list --no-numbers
}

#
# Print numbered content of archive.
# 1 argument is needed - file path
# Returns - 1 if number of arguments is incorrect
#
archive_list_numbered_content()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	echo -e "Index\tName"
	"$AR" "$1" --list
}

#
# Print numbered content of archive in JSON format.
# 1 argument is needed - file path
# Returns - 1 if number of arguments is incorrect
#
archive_list_numbered_content_json()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$AR" "$1" --list --json
}

#
# Get a single file from archive by name.
# 3 arguments are needed - path to the archive
#                        - name of the file
#                        - output path
# Returns - 1 if number of arguments is incorrect
#         - 2 if error occurred
#
archive_get_by_name()
{
	if [ "$#" != "3" ]; then
		return 1
	fi

	if ! "$AR" "$1" --name "$2" --output "$3" &> "$DEV_NULL"; then
		return 2
	fi
}

#
# Get a single file from archive by index.
# 3 arguments are needed - path to the archive
#                        - index of the file
#                        - output path
# Returns - 1 if number of arguments is incorrect
#         - 2 if error occurred
#
archive_get_by_index()
{
	if [ "$#" != "3" ]; then
		return 1
	fi

	if ! "$AR" "$1" --index "$2" --output "$3" &> "$DEV_NULL"; then
		return 2
	fi
}

#
# Check if file is Mach-O universal binary with archives.
# 1 argument is needed - file path
# Returns - 0 if file is archive
#           1 if file is not archive
#
is_macho_archive()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	"$EXTRACT" --list "$1" &> "$DEV_NULL"
}

#
# Check string is a valid decimal number.
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid decimal number.
#           1 otherwise
#
is_decimal_number()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	re='^[0-9]+$'
	if [[ "$1" =~ $re ]] ; then
		return 0
	else
		return 1
	fi
}

#
# Check string is a valid hexadecimal number.
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid hexadecimal number.
#           1 otherwise
#
is_hexadecimal_number()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	re='^0x[0-9a-fA-F]+$'
	if [[ "$1" =~ $re ]] ; then
		return 0
	else
		return 1
	fi
}

#
# Check string is a valid number (decimal or hexadecimal).
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid number.
#           1 otherwise
#
is_number()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	if is_decimal_number "$1"; then
		return 0
	fi

	if is_hexadecimal_number "$1"; then
		return 0
	fi

	return 1
}

#
# Check string is a valid decimal range.
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid decimal range.
#           1 otherwise
#
is_decimal_range()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	re='^[0-9]+-[0-9]+$'
	if [[ "$1" =~ $re ]] ; then
		return 0
	else
		return 1
	fi
}

#
# Check string is a valid hexadecimal range
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid hexadecimal range
#           1 otherwise
#
is_hexadecimal_range()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	re='^0x[0-9a-fA-F]+-0x[0-9a-fA-F]+$'
	if [[ "$1" =~ $re ]] ; then
		return 0
	else
		return 1
	fi
}

#
# Check string is a valid range (decimal or hexadecimal).
# 1 argument is needed - string to check.
# Returns - 0 if string is a valid range
#           1 otherwise
#
is_range()
{
	if [ "$#" != "1" ]; then
		return 1
	fi

	if is_decimal_range "$1"; then
		return 0
	fi

	if is_hexadecimal_range "$1"; then
		return 0
	fi

	return 1
}
