#!/bin/bash
#
# Runs all the installed unit tests.
#

SCRIPTPATH="$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )"

if [ -z "$DECOMPILER_CONFIG" ]; then
	DECOMPILER_CONFIG="$SCRIPTPATH/config.sh"
fi
. "$DECOMPILER_CONFIG"

#
# Emits a colored version of the given message to the standard output (without
# a new line).
#
# 2 string argument are needed:
#    $1 message to be colored
#    $2 color (red, green, yellow)
#
# If the color is unknown, it emits just $1.
#
echo_colored() {
	# Check the number of arguments.
	if [ "$#" != "2" ]; then
		return
	fi

	case $2 in
	"red")
		printf "\033[22;31m$1\033[0m"
		;;
	"green")
		printf "\033[22;32m$1\033[0m"
		;;
	"yellow")
		printf "\033[01;33m$1\033[0m"
		;;
	*)
		printf "$1\n"
		;;
	esac
}

#
# Runs all unit tests in the given directory.
#
# 1 string argument is needed:
#     $1 path to the directory with unit tests
#
# Returns 0 if all tests passed, 1 otherwise.
#
run_unit_tests_in_dir() {
	UNIT_TESTS_DIR="$1"
	TESTS_FAILED="0"
	for unit_test in $(find "$UNIT_TESTS_DIR" -type f -executable | grep -v '\.dll$' | sort); do
		echo ""
		unit_test_name="$(sed 's/^.*\/bin\///' <<< "$unit_test")"
		echo_colored "$unit_test_name" "yellow"
		echo ""
		$unit_test --gtest_color=yes | grep -v "RUN\|OK\|----------\|==========" |\
			grep -v "^$" | grep -v "Running main() from gmock_main.cc"
		RC=${PIPESTATUS[0]}
		if [ "$RC" != "0" ]; then
			TESTS_FAILED="1"
			if [ "$RC" -ge 127 ]; then
				# Segfault, floating-point exception, etc.
				echo_colored "FAILED (return code $RC)\n" "red"
			fi
		fi
	done
	[ "$TESTS_FAILED" = "1" ] && return 1 || return 0
}

#
# Run all binaries in unit test dir.
#
if [ ! -d "$UNIT_TESTS_DIR" ]; then
	echo "error: no unit tests found in $UNIT_TESTS_DIR" >&2
	exit 1
fi

echo "Running all unit tests in $UNIT_TESTS_DIR..."
run_unit_tests_in_dir "$UNIT_TESTS_DIR"
