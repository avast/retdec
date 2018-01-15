/**
* @file include/retdec/utils/string.h
* @brief String utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_STRING_H
#define RETDEC_UTILS_STRING_H

#include <algorithm>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace retdec {
namespace utils {

// We assume that the largest supported character size is 32 bits.
using WideCharType = std::uint32_t;

// Strings may have different character sizes, so we need to use a generic
// basic_string instead of std::string/std::wstring.
using WideStringType = std::basic_string<WideCharType>;

bool hasOnlyDecimalDigits(const std::string &str);

bool hasOnlyHexadecimalDigits(const std::string &str);

bool hasNonprintableChars(const std::string &str);
bool hasNonasciiChars(const std::string &str);

bool isLowerThanCaseInsensitive(const std::string &str1,
	const std::string &str2);

bool areEqualCaseInsensitive(const std::string &str1, const std::string &str2);

bool isShorterPrefixOfCaseInsensitive(const std::string &str1,
	const std::string &str2);

bool contains(const std::string &str, const std::string &sub);
bool containsAny(const std::string &str, const std::vector<std::string> &subs);

bool containsCaseInsensitive(const std::string &str, const std::string &sub);

bool containsAnyOfChars(const std::string &str, const std::string &chars);
bool containsAnyOfChars(const std::string &str, std::string::value_type c);

std::string toLower(std::string str);
std::string toUpper(std::string str);

std::string toWide(const std::string &str, std::string::size_type length);

std::string trim(std::string str, const std::string &toTrim = " \t\r\n\v");

std::vector<std::string> split(const std::string &str, char sep = ',',
	bool trimWhitespace = true);

std::string unifyLineEnds(const std::string &str);

/**
* @brief Joins all the strings in @a strings into a single string.
*
* @param[in] strings Strings to be joined.
* @param[in] separator Separator to separate individual strings.
*
* @tparam Container Type of @a strings.
*
* If Container is an unordered container, the order depends on the
* implementation of the container.
*/
template<typename Container>
std::string joinStrings(const Container &strings,
		const std::string &separator = ", ") {
	std::string joined;
	for (auto &s : strings) {
		if (!joined.empty()) {
			joined += separator;
		}
		joined += s;
	}
	return joined;
}

// The number 4 below is needed because of the null byte.
std::string addSlashes(const std::string &str,
	const std::string &toBackslash = std::string("\"'\\\0", 4));

std::string replaceCharsWithStrings(const std::string &str, char what,
	const std::string &withWhat);

/**
* @brief Returns @c true if @a str starts with the prefix @a withWhat, @c false
*        otherwise.
*
* @tparam String Either @c std::string or <code>char *</code>.
*/
template<typename String>
bool startsWith(const std::string &str, const String &withWhat) {
	return str.find(withWhat, 0) == 0;
}

bool endsWith(const std::string &str, const std::string &withWhat);
bool endsWith(const std::string &str, char withWhat);
bool hasSubstringOnPosition(const std::string &str,
	const std::string &withWhat,
	std::string::size_type position);
bool hasSubstringInArea(const std::string &str, const std::string &withWhat,
	std::string::size_type start, std::string::size_type stop);

bool isComposedOnlyOfChars(const std::string &str, const std::string &chars);
bool isComposedOnlyOfChars(const std::string &str, std::string::value_type c);

bool isComposedOnlyOfStrings(const std::string &str, const std::string &ss);

std::string stripDirs(const std::string &path);

std::string replaceAll(const std::string &str, const std::string &from,
	const std::string &to);

std::string replaceNonprintableChars(const std::string &str);
std::string replaceNonasciiChars(const std::string &str);
std::string replaceNonalnumCharsWith(const std::string &str, std::string::value_type c);

std::string removeWhitespace(std::string s);

std::pair<std::size_t, std::size_t> getLineAndColumnFromPosition(
	const std::string &json, std::size_t position);

bool isNumber(const std::string &str);
bool isIdentifier(const std::string &str);
bool isPrintable(const std::string &str);

std::string removeLeadingCharacter(
	const std::string &s,
	char leading,
	std::size_t n = std::numeric_limits<std::size_t>::max());

bool isContolCharacter(char c);
bool isNiceCharacter(unsigned char c);
bool isNiceString(const std::string &str, double maxRatio = 2.0/3);
bool isNiceAsciiWideCharacter(unsigned long long c);
bool isNiceAsciiWideString(
		const std::vector<unsigned long long> &str,
		double minRatio = 1.0);

std::string getIndentation(std::size_t count, char c = '\t');

void appendHex(std::string &n, const long long a);
void appendDec(std::string &n, const long long a);
std::string appendHexRet(const std::string &n, const long long a);
std::string appendDecRet(const std::string &n, const long long a);
void removeSuffix(std::string &n, const std::string &suffix = "_");
std::string removeSuffixRet(const std::string &n,
	const std::string &suffix = "_");

// TODO: This is the same as toHex() in conversion.h
// Use implementation in conversion.h, but make it to take uint64_t or template.
std::string toHexString(unsigned long long val);

std::string normalizeName(const std::string &name);
std::string normalizeNamePrefix(const std::string &name);

bool findFirstInEmbeddedLists(std::size_t &pos, const std::string &str,
	char c, const std::vector<std::pair<char, char>> &pairs);

std::string removeConsecutiveSpaces(const std::string& str);

std::string asEscapedCString(const WideStringType& value, std::size_t charSize);

std::string removeComments(const std::string& str, char commentChar);

} // namespace utils
} // namespace retdec

#endif
