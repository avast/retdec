/**
* @file src/llvmir2hll/utils/string.cpp
* @brief Implementation of the string utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>
#include <vector>

#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/string.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

using retdec::utils::hasOnlyDecimalDigits;
using retdec::utils::hasOnlyHexadecimalDigits;
using retdec::utils::split;
using retdec::utils::startsWith;
using retdec::utils::toHex;
using retdec::utils::toLower;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Replaces invalid characters by valid ones in the given identifier.
*
* @e Invalid means that it cannot be a part of an identifier in any HLL. A
* single character may be replaced with several characters.
*/
std::string makeIdentifierValid(const std::string &id) {
	// Create the resulting variable name by converting every invalid
	// character in it into its hexadecimal representation.
	//
	// Exceptions:
	//   - dots are converted into underscores to improve code readability
	std::string resId;
	resId.reserve(id.size());
	for (auto c : id) {
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
				(c >= '0' && c <= '9') || c == '_') {
			resId += c;
		} else if (c == '.') {
			resId += '_';
		} else {
			resId += "_" + toHex(c) + "_";
		}
	}
	return resId;
}

/**
* @brief Returns the address extracted from the given name.
*
* @param[in] name Name from which the address should be extracted.
* @param[in] prefix If the extracted address is non-empty, this prefix is
*            prepended before it.
*
* If the address cannot be extracted, it returns the empty string.
*
* Possible formats of names and their extracted addresses:
* @code
*  - xxx_8900438    ->  8900438
*  - xxx_8900438_1  ->  8900438_1
* @endcode
*/
std::string getAddressFromName(const std::string &name,
		const std::string &prefix) {
	// The name should be of the form x_y(_z), where _z is an optional suffix,
	// y is the address, and x is a prefix of the name.
	auto nameParts = split(name, '_');
	if (nameParts.size() < 2) {
		// Not enough parts.
		return "";
	}

	// First, we assume that there are both an address and a suffix, and we
	// check this assumption.
	auto optSuffix = nameParts[nameParts.size() - 1];
	if (optSuffix.empty()) {
		// Do not consider names ending with _ as names that can contain an
		// address.
		return "";
	}
	auto address = nameParts[nameParts.size() - 2];
	if (optSuffix.empty() || optSuffix.size() > 2 ||
			!hasOnlyDecimalDigits(optSuffix)) {
		// There is no suffix, so assume that the last part of the name is the
		// address.
		address = optSuffix;
		optSuffix = "";
	}

	// Check the length of the address. The number 4 below can be changed for
	// any other reasonable number, such as 6.
	if (address.size() < 4) {
		// Too short to be an address.
		return "";
	}

	// Check that the address is of a correct format.
	if (!hasOnlyHexadecimalDigits(address)) {
		return "";
	}

	if (optSuffix.empty()) {
		return prefix + address;
	}
	return prefix + address + "_" + optSuffix;
}

/**
* @brief Returns the offset extracted from the given name.
*
* @param[in] name Name from which the offset should be extracted.
*
* If the offset cannot be extracted, it returns the empty string.
*
* Possible formats of names and their extracted offsets:
* @code
*  - xxx_-yy    ->  -yy
*  - xxx_+yy    ->  +yy
*  - xxx_yy     ->  +yy
* @endcode
*/
std::string getOffsetFromName(const std::string &name) {
	// The name should be of the form x_Sy, S is a sign (- or +) y is the
	// offset, and x is a prefix of the name.
	auto nameParts = split(name, '_');
	if (nameParts.size() < 2) {
		// Not enough parts.
		return "";
	}

	auto offset = nameParts.back();
	if (offset.size() < 2) {
		// Do not consider names ending with _ or just _+/_- as names that can
		// contain an offset.
		return "";
	}

	// Use + if there is no sign.
	if (offset[0] != '+' && offset[0] != '-') {
		offset = "+" + offset;
	}

	// Check that the offset is of a correct format.
	if (!hasOnlyDecimalDigits(offset.substr(1))) {
		return "";
	}

	return offset;
}

/**
* @brief Tries to extract an address from the given basic block label.
*
* @param[in] label Label name from which the address is extracted.
* @param[in] labelPrefix Expected prefix of @a label.
* @param[in] addressPrefix The prefix to be prepended before the address.
*
* All the hexadecimal numbers in the address are converted to lowercase. If
* there is no address, this function returns @a label.
*
* Examples:
* @code
* pc_89004c5                      (pc_) -> 0x89004c5
* pc_804aa06.backedge             (pc_) -> 0x804aa06
* pc_804abb8.pc_804abb8_crit_edge (pc_) -> 0x804abb8
* @endcode
*/
std::string getAddressFromLabel(const std::string &label,
		const std::string &labelPrefix, const std::string &addressPrefix) {
	// The label should be of the form xAy, where x is labelPrefix, A is the
	// address, and y an optional suffix.
	if (!startsWith(label, labelPrefix)) {
		// The prefix is missing.
		return label;
	}

	// Get the address from the part of the label after the prefix. We stop at
	// the first non-hexadecimal digit.
	auto afterPrefix = toLower(label.substr(labelPrefix.size()));
	auto addressEndPos = afterPrefix.find_first_not_of("0123456789abcdef");
	auto address = afterPrefix.substr(0, addressEndPos);
	if (address.empty()) {
		// The address cannot be empty.
		return label;
	}

	return addressPrefix + address;
}

} // namespace llvmir2hll
} // namespace retdec
