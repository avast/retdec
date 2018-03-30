#!/usr/bin/env bash
#
# Runs all the installed unit tests.
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

SCRIPT_DIR="$(dirname "$(gnureadlink -e "$0")")"

if [ -z "$DECOMPILER_CONFIG" ]; then
	DECOMPILER_CONFIG="$SCRIPT_DIR/retdec-config.sh"
fi
. "$DECOMPILER_CONFIG"

#
# First argument can be verbose.
#
if [ "$1" = "-v" ] || [ "$1" = "--verbose" ]; then
	VERBOSE=1
fi

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
# Prints paths to all unit tests in the given directory.
#
# 1 string argument is needed:
#     $1 path to the directory with unit tests
#
unit_tests_in_dir() {
	# On macOS, find does not support the '-executable' parameter (#238).
	# Therefore, on macOS, we have to use '-perm +111'. To explain, + means
	# "any of these bits" and 111 is the octal representation for the
	# executable bit on owner, group, and other. Unfortunately, we cannot use
	# '-perm +111' on all systems because find on Linux/MSYS2 does not support
	# +. It supports only /, but this is not supported by find on macOS...
	# Hence, we need an if.
	# Note: $OSTYPE below is a Bash variable.
	if [[ "$OSTYPE" == "darwin"* ]]; then
		EXECUTABLE_FLAG="-perm +111"
	else
		EXECUTABLE_FLAG="-executable"
	fi
	find "$1" -name "retdec-tests-*" -type f $EXECUTABLE_FLAG | grep -v '\.sh$' | sort
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
	TESTS_RUN="0"
	for unit_test in $(unit_tests_in_dir "$UNIT_TESTS_DIR"); do
		echo ""
		unit_test_name="$(sed 's/^.*\/bin\///' <<< "$unit_test")"
		echo_colored "$unit_test_name" "yellow"
		echo ""
		if [ "$VERBOSE" ]; then
			$unit_test --gtest_color=yes
		else
			$unit_test --gtest_color=yes | grep -v "RUN\|OK\|----------\|==========" |\
				grep -v "^$" | grep -v "Running main() from gmock_main.cc"
		fi
		RC=${PIPESTATUS[0]}
		if [ "$RC" != "0" ]; then
			TESTS_FAILED="1"
			if [ "$RC" -ge 127 ]; then
				# Segfault, floating-point exception, etc.
				echo_colored "FAILED (return code $RC)\n" "red"
			fi
		fi
		TESTS_RUN="1"
	done
	if [ "$TESTS_FAILED" = "1" ] || [ "$TESTS_RUN" = "0" ]; then
		return 1
	else
		return 0
	fi
}

#
# Run all binaries in unit test dir.
#
if [ ! -d "$UNIT_TESTS_DIR" ]; then
	echo "error: no unit tests found in $UNIT_TESTS_DIR" >&2
	exit 1
fi

echo "Running all unit tests in $UNIT_TESTS_DIR ..."
run_unit_tests_in_dir "$UNIT_TESTS_DIR"
