/**
 * @file src/cpdetect/signatures/avg/signature_checker.cpp
 * @brief Utils for checking signatures format.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/string.h"
#include "retdec/cpdetect/signatures/avg/signature_checker.h"

using namespace retdec::utils;

namespace retdec {
namespace cpdetect {

/**
 * Check if signature pattern contains slash
 * @param pattern Signature pattern
 * @return @c true if @a pattern contains at least one slash, @c false otherwise
 */
bool isSlashed(const std::string &pattern)
{
	return contains(pattern, "/");
}

/**
 * Check if @a pattern is valid signature pattern in our format
 * @param pattern Signature pattern
 * @return @c true if @a pattern is valid signature pattern, @c false otherwise
 */
bool isValidSignaturePattern(const std::string &pattern)
{
	const std::string bodyChars = "0123456789ABCDEF-\?/";
	const std::string allChars = bodyChars + ';';
	return isComposedOnlyOfChars(pattern, allChars)
			&& containsAnyOfChars(pattern, bodyChars)
			&& pattern.find(';') >= pattern.length() - 1;
}

/**
 * Check if @a pattern is valid unslashed signature pattern in our format
 * @param pattern Signature pattern
 * @return @c true if @a pattern is valid unslashed signature pattern, @c false otherwise
 */
bool isValidUnslashedPattern(const std::string &pattern)
{
	return isValidSignaturePattern(pattern) && !isSlashed(pattern);
}

} // namespace cpdetect
} // namespace retdec
