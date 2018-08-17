/**
* @file src/utils/string.cpp
* @brief String utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <algorithm>
#include <cassert>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstddef>
#include <functional>
#include <sstream>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace utils {

namespace {

/**
 * @brief Our alternative to std::isprint() which can be inconsistent for '\t'
 *        - true on windows, false on other systems.
 */
bool isPrintableChar(unsigned char c) {
	return std::isprint(c) && !std::iscntrl(c);
}

/**
* @brief Returns @c true if @c is non-printable character, @c false otherwise.
*/
bool isNonprintableChar(unsigned char c) {
	return !isPrintableChar(c);
}

/**
* @brief Returns @c true if @c is non-ASCII character, @c false otherwise.
*/
bool isNonasciiChar(unsigned char c) {
	return c > 0x7f;
}

/**
* @brief Replace all chars in @a str that satisfy condition @a predicate with
*        their hexadecimal values.
*/
std::string replaceChars(const std::string &str, bool (* predicate)(unsigned char)) {
	std::stringstream result;
	const std::size_t maxC = std::pow(2, sizeof(std::string::value_type) * CHAR_BIT) - 1;
	for (const auto &c : str) {
		if (predicate(c)) {
			const auto val = numToStr<std::size_t>(c & maxC, std::hex);
			result << "\\x" << std::setw(2) << std::setfill('0') << val;
		} else {
			result << c;
		}
	}
	return result.str();
}

//
// ============================================================================
//

/**
* @brief Returns the number of hexadecimal digits that are needed to emit a
*        character with the given size (number of bits).
*/
std::size_t widthOf(std::size_t charSize) {
	// Two digits for 8-bit char, four digits for 16-bit char, etc.
	return charSize / 4;
}

/**
* @brief Is the given character within the range of ASCII characters?
*/
bool isASCII(WideCharType c) {
	// ASCII is a 7-bit code.
	return c < 128;
}

/**
* @brief Checks if the given character is printable.
*/
bool isPrintable(WideCharType c) {
	// Functions from <ctypes> do not work when the character does not fit into
	// 'unsigned char' (it's undefined behavior), so before calling them, we
	// have to ensure that the character is in the ASCII range.
	if (!isASCII(c)) {
		return false;
	}

	// std::isprint() returns true for all characters with an ASCII code
	// greater than 0x1f (US), except 0x7f (DEL). However, we also want to
	// consider other characters as printable in the form of escape sequences.
	return isPrintableChar(c) || std::isspace(c) || c == '\a' || c == '\b';
}

/**
* @brief Checks if the given character is either printable or the zero byte.
*/
bool isPrintableOrZeroByte(WideCharType c) {
	return isPrintable(c) || c == '\0';
}

/**
* @brief Checks if the given string has any unprintable characters.
*/
bool hasUnprintableChars(const WideStringType &str) {
	return std::find_if(str.begin(), str.end(),
		std::not1(std::ptr_fun(isPrintable))) != str.end();
}

/**
* @brief Checks if the only unprintable characters in the given string are zero
*        bytes.
*/
bool onlyUnprintableCharsAreZeroBytes(const WideStringType &str) {
	return std::find_if(str.begin(), str.end(),
		std::not1(std::ptr_fun(isPrintableOrZeroByte))) == str.end();
}

/**
* @brief Converts the given character into a hexadecimal representation to be
*        used in escaped C strings.
*
* @param[in] c Character to be converted.
* @param[in] charSize How large is actually the character in @a c (in bits)?
*
* For example, @c ';' is converted into @c "\x3b" when @c charSize is 8.
*/
std::string charToHexaStringRepr(WideCharType c, std::size_t charSize) {
	std::stringstream stringRepr;
	stringRepr << "\\x"
		<< std::setfill('0') << std::setw(widthOf(charSize))
		<< std::hex << c;
	return stringRepr.str();
}

/**
* @brief Can the given character be appended literally, i.e. without escaping
*        it?
*
* @param[in] c Character to be checked.
* @param[in] lastWasHex Was the last character a hexadecimal escape?
*/
bool canBeAppendedLiterally(WideCharType c, bool lastWasHex) {
	// Functions from <ctypes> do not work when the character does not fit into
	// 'unsigned char' (it's undefined behavior), so before calling them, we
	// have to ensure that the character is in the ASCII range.
	if (!isASCII(c)) {
		return false;
	}

	// Only printable characters can be appended literally. However, we have to
	// be careful when the last character output was a hexadecimal escape code,
	// in which case we cannot append hexadecimal digits explicitly (they may
	// be considered as a continuation of the previous character, e.g. "\x00a"
	// is a single character).
	return isPrintableChar(c) && (!lastWasHex || !std::isxdigit(c));
}

/**
* @brief Converts the given character into a representation usable in escaped C
*        strings.
*
* @param[in] c Character to be converted.
* @param[in] charSize How large is actually the character in @a c (in bits)?
* @param[int,out] lastWasHex Was the last character a hexadecimal escape?
* @param[in] forceHex Convert @a c into a hexadecimal escape sequence, even if
*                     it is printable.
*/
std::string charToEscapedCStringRepr(WideCharType c,
		std::size_t charSize, bool &lastWasHex, bool forceHex) {
	if (forceHex) {
		lastWasHex = true;
		return charToHexaStringRepr(c, charSize);
	}

	if (canBeAppendedLiterally(c, lastWasHex)) {
		lastWasHex = false;
		std::string repr;
		if (c == '"' || c == '\\') {
			repr += '\\';
		}
		repr += c;
		return repr;
	}

	// The following list of escape sequences is based on
	// http://en.cppreference.com/w/c/language/escape
	//
	// Note: Although ? (question mark) and ' (single quote) can be written as
	//       escape sequences (see the link above), we generate them normally
	//       because this makes the string more readable.
	lastWasHex = false;
	switch (c) {
		case '\a': return "\\a";
		case '\b': return "\\b";
		case '\f': return "\\f";
		case '\n': return "\\n";
		case '\r': return "\\r";
		case '\t': return "\\t";
		case '\v': return "\\v";
		default: break;
	}

	lastWasHex = true;
	return charToHexaStringRepr(c, charSize);
}

} // anonymous namespace

/**
* @brief Returns @c true if the given string is formed only by decimal digits.
*
* The empty string is considered to be composed only by digits.
*/
bool hasOnlyDecimalDigits(const std::string &str) {
	return std::all_of(str.begin(), str.end(),
		[](const unsigned char c) { return std::isdigit(c); });
}

/**
* @brief Returns @c true if the given string is formed only by hexadecimal
*        digits.
*
* The empty string is considered to be composed only by hexadecimal digits.
*/
bool hasOnlyHexadecimalDigits(const std::string &str) {
	return std::all_of(str.begin(), str.end(),
		[](const unsigned char c) { return std::isxdigit(c); });
}

/**
* @brief Returns @c true if the given string contains at least one
*        non-printable character.
*/
bool hasNonprintableChars(const std::string &str) {
	return std::any_of(str.begin(), str.end(),
		[](const unsigned char c) { return isNonprintableChar(c); });
}

/**
* @brief Returns @c true if the given string contains at least one
*        non-ASCII character.
*/
bool hasNonasciiChars(const std::string &str) {
	return std::any_of(str.begin(), str.end(),
		[](const unsigned char c) { return isNonasciiChar(c); });
}

/**
* @brief Checks if <tt>str1 < str2</tt> (case-insensitively).
*
* This function doesn't consider non-ASCII character sets.
*/
bool isLowerThanCaseInsensitive(const std::string &str1, const std::string &str2) {
	for (std::string::size_type i = 0, e = std::min(str1.size(), str2.size());
			i < e; ++i) {
		const unsigned char lc = str1[i];
		const unsigned char rc = str2[i];
		if (std::tolower(lc) < std::tolower(rc)) {
			return true;
		} else if (std::tolower(lc) > std::tolower(rc)) {
			return false;
		}
	}
	return str1.size() < str2.size();
}

/**
* @brief Checks if <tt>str1 == str2</tt> (case-insensitively).
*/
bool areEqualCaseInsensitive(const std::string &str1, const std::string &str2) {
	if (str1.size() != str2.size()) {
		return false;
	}

	for (std::string::size_type i = 0, e = str1.size(); i < e; ++i) {
		const unsigned char lc = str1[i];
		const unsigned char rc = str2[i];
		if (std::tolower(lc) != std::tolower(rc)) {
			return false;
		}
	}
	return true;
}

/**
* @brief Checks if the shorter string of @a str1 and @a str2 is a
*        case-insensitive prefix of the longer string.
*/
bool isShorterPrefixOfCaseInsensitive(const std::string &str1,
		const std::string &str2) {
	const auto minLen = std::min(str1.length(), str2.length());
	return areEqualCaseInsensitive(str1.substr(0, minLen), str2.substr(0, minLen));
}

/**
* @brief Checks if @a str contains @a sub.
*/
bool contains(const std::string &str, const std::string &sub) {
	return str.find(sub) != std::string::npos;
}

/**
* @brief Check if at least one string from @a subs is contained in @a str.
*/
bool containsAny(const std::string &str, const std::vector<std::string> &subs) {
	for (auto& s : subs) {
		if (contains(str, s)) {
			return true;
		}
	}
	return false;
}

/**
* @brief Find out if string contains another string, no matter the case.
*
* @param str String to search in.
* @param sub String to search for.
*
* @return @c true if string contains another string, @c false otherwise.
*/
bool containsCaseInsensitive(const std::string &str, const std::string &sub) {
	if (sub.empty()) {
		return true;
	}

	auto it = std::search(
		str.begin(), str.end(),
		sub.begin(), sub.end(),
		[](unsigned char ch1, unsigned char ch2) {
			return std::tolower(ch1) == std::tolower(ch2);
		}
	);
	return (it != str.end());
}

/**
* @brief Returns @c true if @a str contains at least one character from
*        @a chars, @c false otherwise.
*
* If @a chars is the empty string, it returns @c false.
*/
bool containsAnyOfChars(const std::string &str, const std::string &chars) {
	return str.find_first_of(chars) != std::string::npos;
}

/**
* @brief Returns @c true if @a str contains @a c, @c false otherwise.
*/
bool containsAnyOfChars(const std::string &str, std::string::value_type c) {
	return str.find_first_of(c) != std::string::npos;
}

/**
* @brief Converts all characters in @a str to lower case.
*
* For example, <tt>"Crazy Willy"</tt> is converted into <tt>"crazy willy"</tt>.
*/
std::string toLower(std::string str) {
	std::transform(str.begin(), str.end(), str.begin(),
		[](const unsigned char c) { return std::tolower(c); });
	return str;
}

/**
* @brief Converts all characters in @a str to upper case.
*
* For example, <tt>"Crazy Willy"</tt> is converted into <tt>"CRAZY WILLY"</tt>.
*/
std::string toUpper(std::string str) {
	std::transform(str.begin(), str.end(), str.begin(),
		[](const unsigned char c) { return std::toupper(c); });
	return str;
}

/**
* @brief Converts @a str to wide string.
*
* @param[in] str String for conversion.
* @param[in] length Length in bytes of one character in output string.
*                   If length is zero, function returns empty string.
*
* @return Converted string.
*/
std::string toWide(const std::string &str, std::string::size_type length) {
	if (!length) {
		return "";
	}

	const std::string padding(length - 1, '\0');
	std::string result;
	result.reserve(str.length() * length);
	for (auto c : str) {
		result += c + padding;
	}
	return result;
}

/**
* @brief Trims the given string.
*
* @param[in] str String to be trimmed.
* @param[in] toTrim String of characters to be trimmed (removed) from the
*                   beginning and the end of @a str. By default, it contains
*                   all whitespace characters from the ASCII set.
*
* @return Trimmed string.
*
* For example, <tt>trim("  hey there  ", " ")</tt> returns <tt>"hey
* there"</tt>.
*/
std::string trim(std::string str, const std::string &toTrim) {
	// Based on
	// http://www.codeproject.com/Articles/10880/A-trim-implementation-for-std-string
	std::string::size_type pos = str.find_last_not_of(toTrim);
	if (pos != std::string::npos) {
		str.erase(pos + 1);
		pos = str.find_first_not_of(toTrim);
		if (pos != std::string::npos) {
			str.erase(0, pos);
		}
	} else {
		str.erase(str.begin(), str.end());
	}
	return str;
}

/**
* @brief Splits the given string by a separator.
*
* @param[in] str String to be splitted.
* @param[in] sep Separator to be used.
* @param[in] trimWhitespace If @c true, trims whitespace around the separated
*                           strings.
*
* For example,
* @code
* split("; a ; b ; c ;", ';', true)
* @endcode
* returns
* @code
* ["", "a", "b", "c", ""]
* @endcode
*/
std::vector<std::string> split(const std::string &str, char sep, bool trimWhitespace) {
	std::vector<std::string> result;
	std::stringstream ss(str);
	std::string item;
	while (std::getline(ss, item, sep)) {
		result.push_back(trimWhitespace ? trim(item) : item);
	}

	// If the input string ends with the separator, we have to add another
	// empty string to the result. Indeed, the above way throws it away.
	if (!str.empty() && str.back() == sep) {
		result.push_back("");
	}

	return result;
}

/**
* @brief Unifies line ends in the given string to LF.
*
* @return String @a str with unified line ends.

* In a greater detail, this function converts CRLF and CR inside @a str to LF.
*/
std::string unifyLineEnds(const std::string &str) {
	return replaceAll(replaceAll(str, "\r\n", "\n"), "\r", "\n");
}

/**
* @brief Returns @a str with backslashes before characters that need to be
*        quoted, specified in @a toBackslash.
*
* @param[in] str String to be backslashed.
* @param[in] toBackslash List of characters to be backslashed in @a str.
*
* By default, @a toBackslash include a single quote ('), double quote ("), backslash (\)
* and NUL (the zero byte).
*/
std::string addSlashes(const std::string &str, const std::string &toBackslash) {
	std::string result;
	for (const auto &c : str) {
		if (toBackslash.find(c) != std::string::npos) {
			result += "\\";
		}
		result += c;
	}
	return result;
}

/**
* @brief Replaces all occurrences of @a what with @a withWhat in @a str and
*        returns the resulting string.
*/
std::string replaceCharsWithStrings(const std::string &str, char what,
		const std::string &withWhat) {
	std::string result;
	for (const auto &c : str) {
		if (c == what) {
			result += withWhat;
		} else {
			result += c;
		}
	}
	return result;
}

/**
* @brief Retruns @c true if @a str ends with the suffix @a withWhat, @c false
*        otherwise
*/
bool endsWith(const std::string &str, const std::string &withWhat) {
	return (str.length() >= withWhat.length()) &&
		(str.compare(str.length() - withWhat.length(), withWhat.length(), withWhat) == 0);
}

/**
* @brief Retruns @c true if @a str ends with the suffix @a withWhat, @c false
*        otherwise
*/
bool endsWith(const std::string &str, char withWhat) {
	return !str.empty() && str.back() == withWhat;
}

/**
* @brief Returns @c true if @a str has substring @a withWhat on index
*        @a position.
*/
bool hasSubstringOnPosition(const std::string &str,
		const std::string &withWhat, std::string::size_type position) {
	return (position < str.length()) && (str.length() - position >= withWhat.length()) &&
		(str.compare(position, withWhat.length(), withWhat) == 0);
}

/**
* @brief Returns @c true if @a str has substring @a withWhat in area
*        bordered by offsets @a start and @a stop.
*/
bool hasSubstringInArea(const std::string &str, const std::string &withWhat,
		std::string::size_type start, std::string::size_type stop) {
	if (start > stop) {
		return false;
	}

	const auto stopIndex = stop + 1;
	const auto stopIterator = stopIndex < str.size() ?
		str.begin() + stopIndex : str.end();
	return std::search(str.begin() + start, stopIterator, withWhat.begin(),
		withWhat.end()) != stopIterator;
}

/**
* @brief Returns @c true if @a str is composed solely of chars in @a chars, @c
*        false otherwise.
*
* If @a chars is the empty string, it returns @c false.
*/
bool isComposedOnlyOfChars(const std::string &str, const std::string &chars) {
	return str.find_first_not_of(chars) == std::string::npos;
}

/**
* @brief Returns @c true if @a str is composed solely of char @a c, @c false
*        otherwise.
*/
bool isComposedOnlyOfChars(const std::string &str, std::string::value_type c) {
	return str.find_first_not_of(c) == std::string::npos;
}

/**
* @brief Returns @c true if @a str is composed solely of strings @a ss, @c
*        false otherwise.
*
* Examples:
* @code
* isComposedOnlyOfStrings("abcd",   "abcd") -> true
* isComposedOnlyOfStrings("ababab", "ab")   -> true
* isComposedOnlyOfStrings("aaaaa",  "aa")   -> true
* isComposedOnlyOfStrings("",       "")     -> true
* isComposedOnlyOfStrings("ababab", "ba")   -> false
* isComposedOnlyOfStrings("hello",  "")     -> false
* @endcode
*/
bool isComposedOnlyOfStrings(const std::string &str, const std::string &ss) {
	if (str.empty()) {
		// The empty string can be composed only of the empty string.
		return ss.empty();
	}

	if (ss.empty()) {
		// No non-empty string can be composed only of the empty string.
		return false;
	}

	if (ss.size() > str.size()) {
		// A string cannot be formed only by strings of a greater length than
		// the string itself.
		return false;
	}

	if (str.size() % ss.size() == 0) {
		// It suffices to check that str is of the form ss ss ss (without the
		// spaces)...
		for (std::string::size_type i = 0, e = str.size(); i < e; i += ss.size()) {
			if (str.substr(i, ss.size()) != ss) {
				return false;
			}
		}
		return true;
	}

	// Both str and ss have to be composed only of a single character.
	return isComposedOnlyOfChars(str, ss[0]) && isComposedOnlyOfChars(ss, str[0]);
}

/**
* @brief Strips all directories from the given path.
*
* For example, <tt>stripDirs("/home/user/test.c")</tt> returns @c "test.c".
*
* TODO Implement the following functionality:
*      - paths on MS Windows ('\' vs '/')
*      - allow backslashed '/' in file names
*/
std::string stripDirs(const std::string &path) {
	std::size_t endPos = path.find_last_of('/');
	if (endPos + 1 < path.length()) {
		return path.substr(endPos + 1);
	}
	return path;
}

/**
* @brief Replaces all occurrences of @a from in @a str with @a to and returns
*        the string obtained in this way.
*
* If @a from is the empty string, it returns @a str.
*/
std::string replaceAll(const std::string &str, const std::string &from,
		const std::string &to) {
	if (from.empty())
		return str;

	std::string result(str);
	std::size_t startPos = 0;
	while ((startPos = result.find(from, startPos)) != std::string::npos) {
		result.replace(startPos, from.length(), to);
		startPos += to.length();
	}
	return result;
}

/**
* @brief Replaces non-printable characters in @a str with their hexadecimal
*        values.
*/
std::string replaceNonprintableChars(const std::string &str) {
	return replaceChars(str, isNonprintableChar);
}

/**
* @brief Replaces non-ASCII characters in @a str with their hexadecimal
*        values.
*/
std::string replaceNonasciiChars(const std::string &str) {
	return replaceChars(str, isNonasciiChar);
}

/**
* @brief Replaces non-alphanumeric characters in @a str with @a c.
*/
std::string replaceNonalnumCharsWith(const std::string &str, std::string::value_type c) {
	std::string result;
	for(const unsigned char s : str) {
		result += isalnum(s) ? s : c;
	}
	return result;
}

/**
* @brief Removes all whitespace from the given string.
*/
std::string removeWhitespace(std::string s) {
	s.erase(std::remove_if(s.begin(), s.end(),
		[](const unsigned char c) { return std::isspace(c); }), s.end());
	return s;
}

/**
* @brief Transform @a position in @c json into line and column location.
*
* @param json JSON string.
* @param position Byte distance from start of JSON string.
*
* @return Pair <tt>(line, column)</tt>.
*/
std::pair<std::size_t, std::size_t> getLineAndColumnFromPosition(const std::string &json,
		std::size_t position) {
	std::size_t line = 0;
	std::size_t column = 0;

	if (position >= json.size())
		return {line, column};

	for (std::size_t p = 0; p < position; ++p) {
		if (json[p] == '\r' && (p + 1) < json.size() && json[p + 1] == '\n') {
			++p;
			++line;
			column = 0;
		} else if (json[p] == '\n') {
			++line;
			column = 0;
		} else {
			++column;
		}
	}

	// column & line start at 1
	return {line + 1, column + 1};
}

/**
* @brief Checks if the string is a number.
*/
bool isNumber(const std::string &str) {
	if (str.length() < 1)
		return false;

	unsigned k = 0;
	if (str[0] == '-' || str[0] == '+')
		k++;

	for (unsigned i = k; i < str.length(); i++) {
		if (!isdigit(static_cast<unsigned char>(str[i])))
			return false;
	}

	return true;
}

/**
 * @brief Checks if the string is a valid C language identifier.
 *
 * Empty string is not valid identifier.
 */
bool isIdentifier(const std::string &str)
{
	if (str.empty())
		return false;

	if (str[0] != '_' && !isalpha(static_cast<unsigned char>(str[0])))
		return false;

	for (std::size_t i = 1; i < str.size(); ++i) {
		if (str[i] != '_' && !isalnum(static_cast<unsigned char>(str[i])))
			return false;
	}

	return true;
}

/**
 * @brief Checks if the string is printable.
 *
 * Empty string is considered printable. This is different from isNiceString
 * because this function considers only printable characters, not control ones.
 *
 * @param str input string
 * @return @c true if input string is printable, @c false otherwise.
 */
bool isPrintable(const std::string &str)
{
	for (unsigned char c : str) {
		if (!isPrintableChar(c)) {
			return false;
		}
	}

	return true;
}

/**
* @brief Removes @c n @c leading characters from the given string @c s and
*        returns the result.
*
* @param s String from which leading characters are tp be removed.
* @param leading Leading character to remove.
* @param n Max number of characters to remove. If not set, remove as much
*          as possible.
*/
std::string removeLeadingCharacter(const std::string &s, char leading, std::size_t n) {
	if (n == 0) {
		return s;
	}

	std::string ret(s);
	std::size_t counter = 0;
	while (ret[0] == leading) {
		ret.erase(0, 1);
		if (n == ++counter) {
			return ret;
		}
	}
	return ret;
}

/**
 * @return @c True if character @a c is a control character, @c false otherwise.
 */
bool isContolCharacter(char c) {
	return c=='\b' || c=='\f' || c=='\n' || c=='\r' || c=='\t' || c=='\v';
}

/**
 * @return @c True if character @a c is a nice character (printable or control).
 *         @c False otherwise.
 */
bool isNiceCharacter(unsigned char c) {
	return isPrintableChar(c) || isContolCharacter(c);
}

/**
* @brief Does the provided string seem nice, i.e ratio of printable characters
*        and escape sequences in the string is at least @p minRatio.
*
* @param str String to check.
* @param minRatio Minimum ratio of printable characters.
*
* @return @c True if the string seems nice, @c false otherwise.
*
* Empty string is never nice.
*/
bool isNiceString(const std::string &str, double minRatio) {
	assert(0.0 <= minRatio && minRatio <= 1.0);

	std::string s = str;
	if (!s.empty() && s.back() == '\00')
		s.pop_back();

	auto niceCharCount = std::count_if(s.begin(), s.end(), isNiceCharacter);
	return !s.empty() && (niceCharCount) >= (s.size() * minRatio);
}

/**
 * @return @c True if character @a c is a nice ASCII wide character.
 *         @c False otherwise.
 */
bool isNiceAsciiWideCharacter(unsigned long long c) {
	return c <= 0xff && isNiceCharacter(c);
}

/**
 * @brief Does the provided wide string consist only from ASCII characters and is nice?
 *        Nice string have ration of printable characters and escape sequences in the
 *        string is at least @p minRatio. Empty string is never nice.
 * @param str Wide string to check.
 * @param minRatio Minimum ratio of printable characters.
 * @return @c True if the string seems nice, @c false otherwise.
 */
bool isNiceAsciiWideString(const std::vector<unsigned long long> &str, double minRatio) {
	assert(0.0 <= minRatio && minRatio <= 1.0);

	auto s = str;
	if (!s.empty() && s.back() == 0)
		s.pop_back();

	auto niceCnt = std::count_if(s.begin(), s.end(), isNiceAsciiWideCharacter);
	return !s.empty() && (niceCnt) >= (s.size() * minRatio);
}

/**
* @brief Returns an indentation string containing the specified number of
*        characters.
*/
std::string getIndentation(std::size_t count, char c) {
	return std::string(count, c);
}

/**
* @brief Appends hexadecimal address to string (typically object name).
*
* @param n Reference to string.
* @param a Address to append.
*/
void appendHex(std::string &n, const long long a) {
	std::stringstream ss;
	ss << n << "_" << std::hex << a;
	n = ss.str();
}

/**
* @brief Appends hexadecimal address to string (typically object name).
*
* @param n Reference to string.
* @param a Address to append.
*/
void appendDec(std::string &n, const long long a) {
	std::stringstream ss;
	ss << n << "_" << std::dec << a;
	n = ss.str();
}

/**
* @brief Appends hexadecimal address to string and return new string.
*
* @param n Original to string.
* @param a Address to append.
*
* @return Copy of original string with hexadecimal address.
*/
std::string appendHexRet(const std::string &n, const long long a) {
	std::stringstream ss;
	ss << n << "_" << std::hex << a;
	return ss.str();
}

/**
* @brief Appends hexadecimal address to string and return new string.
*
* @param n Original to string.
* @param a Address to append.
*
* @return Copy of original string with hexadecimal address.
*/
std::string appendDecRet(const std::string &n, const long long a) {
	std::stringstream ss;
	ss << n << "_" << std::dec << a;
	return ss.str();
}

/**
* @brief Finds the last occurrence of the specified suffix and removes
*        everything from its start to the end.
*
* @param[out] n Reference to string.
* @param[in] suffix Suffix to find and remove.
*/
void removeSuffix(std::string &n, const std::string &suffix) {
	std::size_t found = n.rfind(suffix);
	if (found != std::string::npos) {
		n = n.substr(0, found);
	}
}

/**
* @brief Finds the last occurrence of the specified suffix and removes
*        everything from its start to the end.

* @param[in] n Source string.
* @param[in] suffix Suffix to find and remove.
*
* @return Copy of source string without suffix address.
*/
std::string removeSuffixRet(const std::string &n, const std::string &suffix) {
	std::string ret = n;
	std::size_t found = ret.rfind(suffix);
	if (found != std::string::npos) {
		ret = ret.substr(0, found);
	}
	return ret;
}

/**
* @brief Returns hex-string form of the given integer.
*/
std::string toHexString(unsigned long long val) {
	std::stringstream ss;
	ss << std::hex << val;
	return ss.str();
}

/**
* @brief Replaces all special symbols by their normalized equivalent.
*
* @param[in] name Input string.
*
* @return String with substituted special symbols.
*/
std::string normalizeName(const std::string &name) {
	std::string res;
	for (unsigned i = 0; i < name.length(); i++) {
		switch (name[i]) {
			case '<':
				res += "_lt_"; // less than
				break;
			case '>':
				res += "_gt_"; // great than
				break;
			case '[':
				res += "_lsb_"; // left square bracket
				break;
			case ']':
				res += "_rsb_"; // right square bracket
				break;
			case '(':
				res += "_lb_"; // left bracket
				break;
			case ')':
				res += "_rb_"; // right bracket
				break;
			case ',':
				res += "_comma_";
				break;
			case '~':
				res += "_destructor_";
				break;
			case '*':
				res += "_ptr_";
				break;
			case '&':
				res += "_ampersand_";
				break;
			case '=':
				res += "_eq_";
				break;
			case '!':
				res += "_not_";
				break;
			case '?':
				res += "_qm_"; // question mark
				break;
			case ' ':
			case '`':
			case '\'':
			case '@':
			case ':':
			case '\n':
			case '\r':
				res += '_';
				break;
			case '.':
				res += name[i];
				break;
			default:
				if (isalnum(static_cast<unsigned char>(name[i])))
					res += name[i];
				else
					res += '_';
				break;
		}
	}

	if (!res.empty() && isdigit(static_cast<unsigned char>(res[0]))) {
		res = "_" + res;
	}

	return res;
}

/**
 * TODO: Is this and @c normalizeName() really needed/wanted?
 * If so, can they be merged into one. If not remove them.
 */
std::string normalizeNamePrefix(const std::string &name)
{
	static const std::vector<std::string> prefixesToRemove = {
			"__GI_",
			"__isoc99_",
			"_isoc99_"};

	std::string ret = name;
	for (auto& p : prefixesToRemove)
	{
		if (startsWith(ret, p))
		{
			ret = ret.substr(p.size());
		}
	}
	return ret;
}

/**
* @brief Finds the first occurrence of @c c character in string @c str that is
*        outside of embedded lists delimited by @c pairs.
*
* @param[out] pos Character position of @c std::string::npos if character not
*                 found. Position is left unchanged, if @c true is returned.
* @param str String to find occerrences in.
* @param c Character to find.
* @param pairs Vector of delimiter pairs: @c <delim_start,delim_end>.
*
* @return @c False if substring before the first found occurrence is ok (delimiter
*         pairs match each other), @c true otherwise.
*
* The check is performed only before the occurrence is found, after that,
* string may not be ok. Only delimiter numbers are checked, not their correct
* positions. For example, this is malformed string because delimiters
* (<tt>"{}"</tt>) do not match before character <tt>','</tt> we search for:
* <tt>"{abc{},def"</tt>. However, this is currently ok (search for
* <tt>','</tt>, delimiters <tt>"{}()"</tt>): <tt>"{a(b}c),def"</tt>.
*/
bool findFirstInEmbeddedLists(std::size_t &pos, const std::string &str,
		char c, const std::vector<std::pair<char, char>> &pairs) {
	if (str.empty()) {
		pos = std::string::npos;
		return false;
	}

	std::map<std::pair<char, char>, unsigned> counters;
	for (const auto &p : pairs) {
		counters[p] = 0;
	}

	for (std::size_t i = 0; i < str.size(); ++i) {
		for (const auto &p : pairs) {
			if (str[i] == p.first) {
				++counters[p];
			}
			if (str[i] == p.second) {
				if (counters[p] > 0) {
					--counters[p];
				}
				else {
					return true;
				}
			}
		}

		if (str[i] == c) {
			bool ok = true;
			for (const auto &p : pairs) {
				if (counters[p] > 0) {
					ok = false;
					break;
				}
			}

			if (!ok) {
				continue;
			}

			pos = i;
			return false;
		}
	}

	for (const auto &p : pairs) {
		if (counters[p] > 0) {
			return true;
		}
	}

	pos = std::string::npos;
	return false;
}

std::string removeConsecutiveSpaces(const std::string& str)
{
	std::string ret = str;
	ret.erase(
			std::unique(ret.begin(), ret.end(),
					[](char a, char b) { return a == ' ' && b == ' '; } ),
			ret.end() );
	return ret;
}

/**
* @brief Returns the constant's value as an escaped C string.
*/
std::string asEscapedCString(const WideStringType& value, std::size_t charSize) {
	// Keep track whether the last character was written as a hexadecimal
	// escape.
	bool lastWasHex = false;

	// When the string has any unprintable characters, convert all its
	// characters into hexadecimal escape sequences.
	bool forceHex = hasUnprintableChars(value);

	// However, if the only unprintable characters are zero bytes, do not force
	// the hexadecimal escape because
	//
	//     "hello_world.f\x00"
	//
	// looks better than
	//
	//     "\x68\x65\x6C\x6C\x6F\x5F\x77\x6F\x72\x6C\x64\x2E\x66\x00"
	//
	if (onlyUnprintableCharsAreZeroBytes(value)) {
		forceHex = false;
	}

	// Perform the conversion.
	std::string escapedCString;
	for (auto c : value) {
		escapedCString += charToEscapedCStringRepr(c, charSize, lastWasHex, forceHex);
	}
	return escapedCString;
}

/**
 * Remove comments from string. Comment must start with a single @c commentChar
 * character and end on new line (i.e. '\n') character.
 * For example LLVM comment:
 *    %a = add i32 0, 0 ; this part will be removed
 * @param str         String from which to remove comments.
 * @param commentChar Character used to start the comment (e.g. ';').
 * @return String without comments.
 */
std::string removeComments(const std::string& str, char commentChar)
{
	std::string ret = str;
	bool ers = false;
	for (auto it = ret.begin(); it != ret.end(); )
	{
		if (*it == commentChar)
		{
			it = ret.erase(it);
			ers = true;
		}
		else if (*it == '\n')
		{
			ers = false;
			++it;
		}
		else if (ers)
		{
			it = ret.erase(it);
		}
		else
		{
			++it;
		}
	}
	return ret;
}

} // namespace utils
} // namespace retdec
