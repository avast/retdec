/**
 * @file src/unpackertool/plugins/mpress/mpress_exceptions.h
 * @brief Exception specific for MPRESS plugin.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGINS_MPRESS_MPRESS_EXCEPTIONS_H
#define UNPACKERTOOL_PLUGINS_MPRESS_MPRESS_EXCEPTIONS_H

#include "unpacker/unpacker_exception.h"

namespace unpackertool {
namespace mpress {

/**
 * Thrown when no section with packed data was found.
 *
 * This exception should report unsupported file.
 */
class PackedDataSectionNotFoundException : public unpacker::UnsupportedInputException
{
public:
	explicit PackedDataSectionNotFoundException() : UnsupportedInputException("Section with packed data not found.") {}
};

/**
 * Thrown when import hints are invalid.
 */
class InvalidImportHintsException : public unpacker::FatalException
{
public:
	explicit InvalidImportHintsException() : FatalException("Invalid import hints detected.") {}
};

/**
 * Thrown when unpacking stub is corrupted.
 */
class CorruptedUnpackingStubException : public unpacker::FatalException
{
public:
	explicit CorruptedUnpackingStubException() : FatalException("Corrupted unpacking stub detected.") {}
};

} // namespace mpress
} // namespace unpackertool

#endif
