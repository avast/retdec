/**
 * @file src/cpdetect/errors.cpp
 * @brief File for error functions.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <unordered_map>

#include "retdec/utils/container.h"
#include "retdec/utils/string.h"
#include "retdec/cpdetect/errors.h"
#include "retdec/fileformat/utils/other.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

namespace
{

/**
 * Default error message
 */
const std::string defaultError = "Error: Unknown error.";

/**
 * Error messages of library
 */
const std::unordered_map<ReturnCode, std::string, retdec::utils::EnumClassKeyHash> errorMessages =
{
	{
		ReturnCode::OK,
		""
	},
	{
		ReturnCode::ARG,
		"Error: Invalid arguments."
	},
	{
		ReturnCode::FILE_NOT_EXIST,
		"Error: The input file probably not exist or it is incorrect."
	},
	{
		ReturnCode::FILE_PROBLEM,
		"Error: Problem occurred during processing the input file."
	},
	{
		ReturnCode::UNKNOWN_FORMAT,
		"Error: File format of the input file is not supported."
	},
	{
		ReturnCode::FORMAT_PARSER_PROBLEM,
		"Error: Failed to parse the input file (it is probably corrupted)."
	},
	{
		ReturnCode::MACHO_AR_DETECTED,
		"Error: File is a fat Mach-O binary with archives. Extract objects before using fileinfo."
	},
	{
		ReturnCode::ARCHIVE_DETECTED,
		"Error: File is an archive. Use some archive tool (llvm-ar or similar)."
	},
	{
		ReturnCode::ENTRY_POINT_DETECTION,
		"Warning: Invalid address of entry point."
	},
	{
		ReturnCode::UNKNOWN_CP,
		"Warning: Unknown compiler or packer."
	}
};

} // anonymous namespace

/**
 * Get a message describing the error for error code
 * @param errorCode Input error code
 * @param format Detected format (optional)
 * @return Error message
 */
std::string getErrorMessage(ReturnCode errorCode, retdec::fileformat::Format format)
{
	auto str = mapGetValueOrDefault(errorMessages, errorCode, defaultError);
	switch(errorCode)
	{
		case ReturnCode::UNKNOWN_FORMAT:
			return str + " Supported formats: " + joinStrings(getSupportedFileFormats()) + ".";
		case ReturnCode::FORMAT_PARSER_PROBLEM:
			return str + " Detected format is: " + getFileFormatNameFromEnum(format) + ".";
		default:
			return str;
	}
}

/**
 * Returns whether the given error code is fatal error code
 * @return @c true if error is fatal error, @c false otherwise.
 */
bool isFatalError(ReturnCode errorCode)
{
	return errorCode != ReturnCode::OK
		&& errorCode != ReturnCode::ENTRY_POINT_DETECTION
		&& errorCode != ReturnCode::UNKNOWN_CP;
}

} // namespace cpdetect
} // namespace retdec
