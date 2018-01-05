/**
* @file include/retdec/llvmir2hll/utils/string.h
* @brief String utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_UTILS_STRING_H
#define RETDEC_LLVMIR2HLL_UTILS_STRING_H

#include <string>

namespace retdec {
namespace llvmir2hll {

/// @name Operations with Strings
/// @{

std::string makeIdentifierValid(const std::string &id);

std::string getAddressFromName(const std::string &name,
	const std::string &prefix = "0x");

std::string getOffsetFromName(const std::string &name);

std::string getAddressFromLabel(const std::string &label,
	const std::string &labelPrefix,
	const std::string &addressPrefix = "0x");

/// @}

} // namespace llvmir2hll
} // namespace retdec

#endif
