#!/bin/bash
#
# Get RetDec share directory.
#

###############################################################################

VERSION_FILE_NAME="version.txt"
ARCH_SUFFIX="tar.xz"

SHA256SUM_REF="6376af57a77147f1363896963d8c1b3745ddb9a6bcec83d63a5846c3f78aeef9"
VERSION="2017-12-12"

###############################################################################

ARCH_NAME="retdec-support"_"$VERSION.$ARCH_SUFFIX"

cleanup()
{
	rm -f "$INSTALL_PATH/$ARCH_NAME"
	rm -rf "$SHARE_DIR/arm"
	rm -rf "$SHARE_DIR/generic"
	rm -rf "$SHARE_DIR/x86"
	rm -f "$SHARE_DIR/version.txt"
}

# Check arguments.
if [ "$#" -ne 1 ]; then
	echo "ERROR: Unexpected number of arguments."
	exit 1
fi

# Get install path from script options.
INSTALL_PATH="$1"
# Convert from Windows to Unix path on Windows.
case "$(uname -s)" in
	*Windows*|*CYGWIN*|*MINGW*|*MSYS*)
		INSTALL_PATH="$(sed -e 's/\\/\//g' -e 's/://' <<< "/$INSTALL_PATH")"
		;;
esac

SHARE_DIR="$INSTALL_PATH/share"

# Share directory exists.
if [ -d "$SHARE_DIR" ]; then
	# Version file exists.
	if [ -f "$SHARE_DIR/$VERSION_FILE_NAME" ]; then
		VERSION_FROM_FILE=$(cat "$SHARE_DIR/$VERSION_FILE_NAME")
		# Version is ok.
		if [ "$VERSION" = "$VERSION_FROM_FILE" ]; then
			echo "$SHARE_DIR already exists, version is ok"
			exit
		else
			echo "versions is not as expected -> replace with expected version"
		fi
	fi

	cleanup
fi

# Make sure destination directory exists.
mkdir -p "$INSTALL_PATH"

# Get archive using wget.
WGET_PARAMS=("https://github.com/avast-tl/retdec-support/releases/download/$VERSION/$ARCH_NAME" -O "$INSTALL_PATH/$ARCH_NAME")
echo "RUN: wget ${WGET_PARAMS[@]}"
wget "${WGET_PARAMS[@]}"
WGET_RC=$?
if [ "$WGET_RC" -ne 0 ]; then
	echo "ERROR: wget failed"
	cleanup
	exit 1
fi

# Compute hash of the downloaded archive.
SHA256SUM_PARAMS=("$INSTALL_PATH/$ARCH_NAME")
echo "RUN: sha256sum ${SHA256SUM_PARAMS[@]}"
SHA256SUM=$(sha256sum "${SHA256SUM_PARAMS[@]}" | cut -d' ' -f1)
SHA256SUM_RC=$?
if [ "$SHA256SUM_RC" -ne 0 ]; then
	echo "ERROR: sha256sum failed"
	cleanup
	exit 1
fi

# Check that hash is ok.
if [ "$SHA256SUM" != "$SHA256SUM_REF" ]; then
	echo "ERROR: hash check failed"
	cleanup
	exit 1
fi

# Unpack archive.
UNPACK_PARAMS=("$INSTALL_PATH/$ARCH_NAME" "--directory=$INSTALL_PATH")
echo "RUN: tar xf ${UNPACK_PARAMS[@]}"
tar xf "${UNPACK_PARAMS[@]}" &> /dev/null
UNPACK_RC=$?
if [ "$UNPACK_RC" -ne 0 ]; then
	echo "ERROR: unpacking failed"
	cleanup
	exit 1
fi

# Remove archive.
rm -f "$INSTALL_PATH/$ARCH_NAME"

echo "RetDec share directory downloaded OK"
exit
