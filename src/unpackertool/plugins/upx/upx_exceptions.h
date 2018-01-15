/**
 * @file src/unpackertool/plugins/upx/upx_exceptions.h
 * @brief Exception specific for UPX plugin.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_UPX_UPX_EXCEPTIONS_H
#define UNPACKERTOOL_PLUGINS_UPX_UPX_EXCEPTIONS_H

#include "retdec/unpacker/unpacker_exception.h"

namespace retdec {
namespace unpackertool {
namespace upx {

/**
 * Used in ELF unpacking. Thrown when invalid packed block is found. There may be
 * many reasons why block is invalid. Packed data size may be greater than unpacked
 * data size, packed data size may read beyond file bounds, there may be less data
 * available than packed data size reports etc.
 *
 * This exception is fatal error during unpacking.
 */
class InvalidBlockException : public retdec::unpacker::FatalException
{
public:
	InvalidBlockException() : FatalException("Invalid packed block found.") {}
};

/**
 * Used in ELF unpacking. Thrown when unsupported packing method is written in packed
 * block header.
 *
 * This exception should report unsupported file.
 */
class UnsupportedPackingMethodException : public retdec::unpacker::UnsupportedInputException
{
public:
	explicit UnsupportedPackingMethodException(std::uint32_t packingMethod)
		: UnsupportedInputException("Unsupported packing method 0x", std::hex, packingMethod, std::dec, " detected.") {}
};

/**
 * Used in both PE and ELF. Thrown in different cases on both formats. In case of ELF,
 * we have available filter number so we can directly print the unsupproted filter ID.
 * However, in case of PE we don't have this options since filters are matched through
 * signatures and if the signature for unsupported filter is missing then we have no
 * way to tell whether it is unsupported filter or anything else. Thus on PE this
 * exceptions is thrown in case of unimplemented unfiltering for known filter signature.
 *
 * This exception should report unsupported file.
 */
class UnsupportedFilterException : public retdec::unpacker::UnsupportedInputException
{
public:
	explicit UnsupportedFilterException(std::uint32_t filterId) : UnsupportedInputException("Unsupported filter 0x", std::hex, filterId, std::dec, " detected.") {}
};

/**
 * Used in PE. Thrown in case of missing original header in unpacked data. This header
 * is used to obtain information about original section layout.
 *
 * This exception is fatal error during unpacking.
 */
class OriginalHeaderNotFoundException : public retdec::unpacker::FatalException
{
public:
	OriginalHeaderNotFoundException() : FatalException("Original header not found in unpacked data.") {}
};

/**
 * Used in PE. Thrown in case of corrupted data in the original PE header.
 *
 * This exception is fatal error during unpacking.
 */
class OriginalHeaderCorruptedException : public retdec::unpacker::FatalException
{
public:
	OriginalHeaderCorruptedException() : FatalException("Original header contains corrupted data.") {}
};

/**
 * Used in PE. Thrown in case of invalid RVA or size of data directory in PE header.
 *
 * This exception should report unsupported file.
 */
class InvalidDataDirectoryException : public retdec::unpacker::UnsupportedInputException
{
public:
	InvalidDataDirectoryException(const std::string& directoryName) : UnsupportedInputException(directoryName, " data directory is corrupted.") {}
};

/**
 * Used in PE. Thrown in case when ILT with import names wasn't found.
 *
 * This exception is fatal error during unpacking.
 */
class ImportNamesNotFoundException : public retdec::unpacker::FatalException
{
public:
	ImportNamesNotFoundException() : FatalException("Import names for fixing imports not found.") {}
};

/**
 * Used in PE. If entry point section is UPX0 section then the file was most probably unpacked using memory dumping and should not be considered
 *   as valid UPX file.
 *
 * This exception is fatal error during unpacking.
 */
class FileMemoryDumpedException : public retdec::unpacker::FatalException
{
public:
	FileMemoryDumpedException() : FatalException("File is probably unpacked by memory dumping and it is no longer valid UPX file.") {}
};

/**
 * Used in Mach-O. Thrown in case of missing first packed block, or simply the unpacker cannot find it.
 *
 * This exception is fatal error during unpacking.
 */
class FirstBlockNotFoundException : public retdec::unpacker::FatalException
{
public:
	FirstBlockNotFoundException() : FatalException("First packed block not found in the file.") {}
};

/**
 * Used in PE. Thrown when file is for sure not packed with UPX packer.
 *
 * This exception is fatal error during unpacking.
 */
class NotPackedWithUpxException : public retdec::unpacker::FatalException
{
public:
	NotPackedWithUpxException() : FatalException("File is not packed with UPX.") {}
};

} // namespace upx
} // namespace unpackertool
} // namespace retdec

#endif
