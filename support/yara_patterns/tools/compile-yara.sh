#!/bin/sh
#
# Compile and install tool signatures.
# Usage: compile-yara.sh yarac-path source-path install-path
#

###############################################################################

# Print error and exit with non-zero value.
#     $1 - error message.
printErrorAndDie()
{
	if ! [ -z "$1" ]; then
		echo "Error: $1."
	fi
	exit 1
}

# Compile yara signatures.
#     $1 - input folder
#     $2 - output file
compileFiles()
{
	ERR_OUT="$("$CC" -w "$1"/*.yara "$2" 2>&1)"
	if [ $? -ne 0 ]; then
		printErrorAndDie "yarac failed during compilation of file $1"
	fi

	# Check for errors in output - yarac returns 0 when it should not.
	case "$ERR_OUT" in
  *error*)
    printErrorAndDie "yarac failed during compilation of file $1"
    ;;
esac
}

###############################################################################

CC="$1"
if [ -z "$CC" ]; then
	printErrorAndDie "missing path to yarac"
fi

SRC="$2"
if [ -z "$SRC" ]; then
	printErrorAndDie "missing path to rules folder"
fi

OUT="$3"
if [ -z "$OUT" ]; then
	printErrorAndDie "missing path to install folder"
fi

###############################################################################

# Convert from Windows to Unix path on Windows.
case "$(uname -s)" in
	*Windows*|*CYGWIN*|*MINGW*|*MSYS*)
		CC="$(echo "/$CC" | sed -e 's/\\/\//g' -e 's/://')"
		SRC="$(echo "/$SRC" | sed -e 's/\\/\//g' -e 's/://')"
		OUT="$(echo "/$OUT" | sed -e 's/\\/\//g' -e 's/://')"
		;;
esac

# Directory paths.
SRC="$SRC/support/yara_patterns/tools"
OUT="$OUT/share/retdec/support/generic/yara_patterns/tools"

###############################################################################

# Remove old files if present.
rm -rf "$OUT"

# Prepare directory structure.
mkdir -p "$OUT/pe"
mkdir -p "$OUT/elf"
mkdir -p "$OUT/macho"

###############################################################################

echo "compiling yara signatures..."

## Compile PE32 signatures.
compileFiles "$SRC/pe/x86" "$OUT/pe/x86.yarac"
compileFiles "$SRC/pe/arm" "$OUT/pe/arm.yarac"

## Compile PE32+ signatures.
compileFiles "$SRC/pe/x64" "$OUT/pe/x64.yarac"

## Compile ELF signatures.
compileFiles "$SRC/elf/x86" "$OUT/elf/x86.yarac"
compileFiles "$SRC/elf/arm" "$OUT/elf/arm.yarac"
compileFiles "$SRC/elf/ppc" "$OUT/elf/ppc.yarac"
compileFiles "$SRC/elf/mips" "$OUT/elf/mips.yarac"

## Compile ELF64 signatures.
compileFiles "$SRC/elf/x64" "$OUT/elf/x64.yarac"
compileFiles "$SRC/elf/arm64" "$OUT/elf/arm64.yarac"
compileFiles "$SRC/elf/ppc64" "$OUT/elf/ppc64.yarac"
compileFiles "$SRC/elf/mips64" "$OUT/elf/mips64.yarac"

## Compile Mach-O signatures.
compileFiles "$SRC/macho/x86" "$OUT/macho/x86.yarac"
compileFiles "$SRC/macho/arm" "$OUT/macho/arm.yarac"
compileFiles "$SRC/macho/ppc" "$OUT/macho/ppc.yarac"

## Compile 64-bit Mach-O signatures.
compileFiles "$SRC/macho/x64" "$OUT/macho/x64.yarac"
compileFiles "$SRC/macho/ppc64" "$OUT/macho/ppc64.yarac"

echo "signatures compiled successfully"
exit
