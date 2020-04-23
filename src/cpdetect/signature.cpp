/**
 * @file src/cpdetect/signature.cpp
 * @brief Definiton of compiler or packer signature.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/cpdetect/signature.h"

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 * @param sName Name of compiler or packer
 * @param sVersion Version of used compiler or packer
 * @param sPattern Signature pattern
 * @param sAdditional Additional information about used compiler or packer
 * @param sStart Start offset of pattern
 * @param sEnd End offset of pattern
 */
Signature::Signature(
		std::string sName,
		std::string sVersion,
		std::string sPattern,
		std::string sAdditional,
		unsigned sStart,
		unsigned sEnd)
		: name(sName)
		, version(sVersion)
		, pattern(sPattern)
		, additional(sAdditional)
		, startOffset(sStart)
		, endOffset(sEnd)
{

}

bool Signature::isValidSignaturePattern(const std::string& pattern)
{
	const std::string bodyChars = "0123456789ABCDEF-\?/";
	const std::string allChars = bodyChars + ';';
	return retdec::utils::isComposedOnlyOfChars(pattern, allChars)
			&& retdec::utils::containsAnyOfChars(pattern, bodyChars)
			&& pattern.find(';') >= pattern.length() - 1;
}

} // namespace cpdetect
} // namespace retdec
