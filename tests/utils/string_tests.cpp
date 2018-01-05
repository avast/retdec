/**
* @file tests/utils/string_tests.cpp
* @brief Tests for the @c string module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/utils/string.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace utils {
namespace tests {

/**
* @brief Tests for the @c string module.
*/
class StringTests: public Test {};

//
// hasOnlyDecimalDigits()
//

TEST_F(StringTests,
HasOnlyDecimalDigitsHasOnlyDecimalDigits) {
	EXPECT_TRUE(hasOnlyDecimalDigits(""));
	EXPECT_TRUE(hasOnlyDecimalDigits("1"));
	EXPECT_TRUE(hasOnlyDecimalDigits("134573908"));
	EXPECT_TRUE(hasOnlyDecimalDigits("0123456789"));

	EXPECT_FALSE(hasOnlyDecimalDigits("b"));
	EXPECT_FALSE(hasOnlyHexadecimalDigits("#"));
	EXPECT_FALSE(hasOnlyDecimalDigits("86c435"));
}

//
// hasOnlyHexadecimalDigits()
//

TEST_F(StringTests,
HasOnlyHexadecimalDigitsHasOnlyHexadecimalDigits) {
	EXPECT_TRUE(hasOnlyHexadecimalDigits(""));
	EXPECT_TRUE(hasOnlyHexadecimalDigits("1"));
	EXPECT_TRUE(hasOnlyHexadecimalDigits("d"));
	EXPECT_TRUE(hasOnlyHexadecimalDigits("134573908"));
	EXPECT_TRUE(hasOnlyHexadecimalDigits("13f4573908a"));
	EXPECT_TRUE(hasOnlyHexadecimalDigits("012345689abcdef"));

	EXPECT_FALSE(hasOnlyHexadecimalDigits("r"));
	EXPECT_FALSE(hasOnlyHexadecimalDigits("#"));
	EXPECT_FALSE(hasOnlyHexadecimalDigits("86c435g"));
}

//
// hasNonprintableChars()
//

TEST_F(StringTests,
HasNonprintableCharsTrue) {
	EXPECT_TRUE(hasNonprintableChars("\x7F""ELF"));
}

TEST_F(StringTests,
HasNonprintableCharsFalse) {
	EXPECT_FALSE(hasNonprintableChars(""));
	EXPECT_FALSE(hasNonprintableChars("abcd"));
	EXPECT_FALSE(hasNonprintableChars("0123456789ABCDEFGHijklm"));
	EXPECT_FALSE(hasNonprintableChars("ELF"));
}

//
// hasNonasciiChars()
//

TEST_F(StringTests,
HasNonasciiCharsTrue) {
	EXPECT_TRUE(hasNonasciiChars("\x80""ELF"));
}

TEST_F(StringTests,
HasNonasciiCharsFalse) {
	EXPECT_FALSE(hasNonasciiChars(""));
	EXPECT_FALSE(hasNonasciiChars("abcd"));
	EXPECT_FALSE(hasNonasciiChars("0123456789ABCDEFGHijklm"));
	EXPECT_FALSE(hasNonasciiChars("ELF"));
}

//
// contains()
//

TEST_F(StringTests,
ContainsEmptyStringIsContainedInEveryString) {
	EXPECT_TRUE(contains("abcd", ""));
}

TEST_F(StringTests,
ContainsEmptyStringDoesNotContainNonEmptyString) {
	EXPECT_FALSE(contains("", "abcd"));
}

TEST_F(StringTests,
ContainsEmptyStringIsContainedInAnotherEmptyString) {
	ASSERT_TRUE(contains("", ""));
}

TEST_F(StringTests,
ContainsSubstringIsContained) {
	EXPECT_TRUE(contains("abcd", "bc"));
}

TEST_F(StringTests,
ContainsSubstringIsNotContained) {
	EXPECT_FALSE(contains("abcd", "BC"));
}

//
// containsAny()
//

TEST_F(StringTests,
ContainsAnyEmptyStringIsContainedInEveryString) {
	EXPECT_TRUE(containsAny("abcd", {""}));
}

TEST_F(StringTests,
ContainsAnyNoStringIsContained) {
	EXPECT_FALSE(containsAny("abcd", {"ac", "bd", "ad", "acd", "bcba"}));
}

TEST_F(StringTests,
ContainsAnyAtLeastOneStringIsContained) {
	EXPECT_TRUE(containsAny("abcd", {"ac", "bd", "bc"}));
}

//
// containsCaseInsensitive()
//

TEST_F(StringTests,
ContainsCaseInsensitiveEmptyStringIsContainedInEveryString) {
	EXPECT_TRUE(containsCaseInsensitive("abcd", ""));
}

TEST_F(StringTests,
ContainsCaseInsensitiveEmptyStringDoesNotContainOtherString) {
	EXPECT_FALSE(containsCaseInsensitive("", "abcd"));
}

TEST_F(StringTests,
ContainsCaseInsensitiveEmptyStringIsContainedInAnotherEmptyString) {
	ASSERT_TRUE(containsCaseInsensitive("", ""));
}

TEST_F(StringTests,
ContainsCaseInsensitiveSubstringIsContainedWhenCaseMatches) {
	EXPECT_TRUE(containsCaseInsensitive("abcd", "bc"));
}

TEST_F(StringTests,
ContainsCaseInsensitiveSubstringIsContainedEvenWhenCaseDoesNotMatch) {
	EXPECT_TRUE(containsCaseInsensitive("abCd", "Bc"));
}

TEST_F(StringTests,
ContainsCaseInsensitiveWorksEvenWhenStringContainsOtherSymbolsThanLetters) {
	EXPECT_TRUE(containsCaseInsensitive("145_%|E", "45_%|"));
}

TEST_F(StringTests,
ContainsCaseInsensitiveReturnsFalseWhenSubstringIsNotContained) {
	EXPECT_FALSE(containsCaseInsensitive("abcd", "hello"));
}

//
// containsAnyOfChars()
//

TEST_F(StringTests,
ContainsAnyOfCharsTrue) {
	EXPECT_TRUE(containsAnyOfChars("abcd", "axyz"));
	EXPECT_TRUE(containsAnyOfChars("abcd", "xyzb"));
	EXPECT_TRUE(containsAnyOfChars("abcd", 'c'));
}

TEST_F(StringTests,
ContainsAnyOfCharsFalse) {
	EXPECT_FALSE(containsAnyOfChars("abcd", ""));
	EXPECT_FALSE(containsAnyOfChars("abcd", "xyz"));
	EXPECT_FALSE(containsAnyOfChars("abcd", 'x'));
}

//
// isLowerThanCaseInsensitive()
//

TEST_F(StringTests,
IsLowerThanCaseInsensitiveStr1LowerThanStr2) {
	EXPECT_TRUE(isLowerThanCaseInsensitive("", "a"));
	EXPECT_TRUE(isLowerThanCaseInsensitive("A", "ab"));
	EXPECT_TRUE(isLowerThanCaseInsensitive("abc", "abd"));
}

TEST_F(StringTests,
IsLowerThanCaseInsensitiveStr1EqualToStr2) {
	EXPECT_FALSE(isLowerThanCaseInsensitive("", ""));
	EXPECT_FALSE(isLowerThanCaseInsensitive("a", "A"));
	EXPECT_FALSE(isLowerThanCaseInsensitive("A", "a"));
	EXPECT_FALSE(isLowerThanCaseInsensitive("abC", "aBc"));
}

TEST_F(StringTests,
IsLowerThanCaseInsensitiveStr1GreaterThanStr2) {
	EXPECT_FALSE(isLowerThanCaseInsensitive("a", ""));
	EXPECT_FALSE(isLowerThanCaseInsensitive("ab", "A"));
	EXPECT_FALSE(isLowerThanCaseInsensitive("abd", "abc"));
}

//
// areEqualCaseInsensitive()
//

TEST_F(StringTests,
AreEqualCaseInsensitiveReturnsTrueWhenStringsAreEqualCaseInsensitively) {
	EXPECT_TRUE(areEqualCaseInsensitive("AbCdE", "aBcDE"));
}

TEST_F(StringTests,
AreEqualCaseInsensitiveReturnsFalseWhenStringsHaveDifferentLengths) {
	EXPECT_FALSE(areEqualCaseInsensitive("ab", "abcde"));
}

TEST_F(StringTests,
AreEqualCaseInsensitiveReturnsFalseWhenStringsAreNotEqualCaseInsensitively) {
	EXPECT_FALSE(areEqualCaseInsensitive("abcccc", "abdddd"));
}

//
// toLower()
//

TEST_F(StringTests,
ToLowerCorrectConversion) {
	EXPECT_EQ("", toLower(""));
	EXPECT_EQ("a", toLower("a"));
	EXPECT_EQ("abc", toLower("abc"));
	EXPECT_EQ("abc", toLower("AbC"));
	EXPECT_EQ("   crazy willy\n", toLower("   Crazy Willy\n"));
}

//
// toUpper()
//

TEST_F(StringTests,
ToUpperCorrectConversion) {
	EXPECT_EQ("", toUpper(""));
	EXPECT_EQ("A", toUpper("a"));
	EXPECT_EQ("ABC", toUpper("abc"));
	EXPECT_EQ("ABC", toUpper("AbC"));
	EXPECT_EQ("   CRAZY WILLY\n", toUpper("   Crazy Willy\n"));
	EXPECT_EQ("8066643E-7F73-4487-948C", toUpper("8066643e-7f73-4487-948c"));
}

//
// toWide()
//

TEST_F(StringTests,
ToWideCorrectConversion) {
	EXPECT_EQ(toWide("abcd", 0), "");
	EXPECT_EQ(toWide("abcd", 1), "abcd");
	EXPECT_EQ(toWide("abcd", 2), "a\0b\0c\0d\0"s);
	EXPECT_EQ(toWide("abcd", 4), "a\0\0\0b\0\0\0c\0\0\0d\0\0\0"s);
}

//
// trim()
//

TEST_F(StringTests,
TrimNothingToTrim) {
	// Whitespace (the second argument is the default one).
	EXPECT_EQ(std::string("aa"), trim("aa"));

	// Other (the second argument is given).
	EXPECT_EQ(std::string(" bb"), trim(" bb", "cd"));
}

TEST_F(StringTests,
TrimFromBeginning) {
	// Whitespace. Try all kinds of whitespace.
	EXPECT_EQ(std::string("aa"), trim("  aa"));
	EXPECT_EQ(std::string("aa"), trim("\taa"));
	EXPECT_EQ(std::string("aa"), trim("\naa"));
	EXPECT_EQ(std::string("aa"), trim("\vaa"));
	EXPECT_EQ(std::string("aa"), trim("\raa"));

	// Other.
	EXPECT_EQ(std::string("e"), trim("ccdde", "cd"));
}

TEST_F(StringTests,
TrimFromEnd) {
	// Whitespace. Try all kinds of whitespace.
	EXPECT_EQ(std::string("aa"), trim("aa  "));
	EXPECT_EQ(std::string("aa"), trim("aa\t"));
	EXPECT_EQ(std::string("aa"), trim("aa\n"));
	EXPECT_EQ(std::string("aa"), trim("aa\v"));
	EXPECT_EQ(std::string("aa"), trim("aa\r"));

	// Other.
	EXPECT_EQ(std::string("c"), trim("cdeeeee", "ed"));
}

TEST_F(StringTests,
TrimFromBothSides) {
	// Whitespace. Try all kinds of whitespace.
	EXPECT_EQ(std::string("aa"), trim("\taa  "));
	EXPECT_EQ(std::string("aa"), trim("\naa\t"));
	EXPECT_EQ(std::string("aa"), trim("  aa\n"));
	EXPECT_EQ(std::string("aa"), trim("\r\raa\v"));
	EXPECT_EQ(std::string("aa"), trim("   aa\r"));

	// Other.
	EXPECT_EQ(std::string("c"), trim("ddddcdeeeee", "ed"));
}

TEST_F(StringTests,
TrimNoNotTrimFromMiddle) {
	// Whitespace. Try all kinds of whitespace.
	EXPECT_EQ(std::string("a a"), trim("a a"));
	EXPECT_EQ(std::string("a\ta"), trim("a\ta"));
	EXPECT_EQ(std::string("a\na"), trim("a\na"));
	EXPECT_EQ(std::string("a\va"), trim("a\va"));
	EXPECT_EQ(std::string("a\ra"), trim("a\ra"));

	// Other.
	EXPECT_EQ(std::string("cbc"), trim("cbc", "b"));

}

TEST_F(StringTests,
TrimFromEmptyString) {
	// Whitespace.
	EXPECT_EQ(std::string(""), trim(""));

	// Other.
	EXPECT_EQ(std::string(""), trim("", "abc"));
}

TEST_F(StringTests,
TrimResultsInRemovingEverythingFromTheString) {
	// Whitespace.
	EXPECT_EQ(std::string(""), trim("    "));

	// Other.
	EXPECT_EQ(std::string(""), trim("aa", "a"));
}

TEST_F(StringTests,
TrimEmptyToTrimString) {
	EXPECT_EQ(std::string("abc"), trim("abc", ""));
}

//
// split()
//

TEST_F(StringTests,
SplitEmptyStringNoTrim) {
	EXPECT_EQ(std::vector<std::string>(), split("", ';', false));
}

TEST_F(StringTests,
SplitEmptyStringWithTrim) {
	EXPECT_EQ(std::vector<std::string>(), split("", ';', true));
}

TEST_F(StringTests,
SplitNothingToSplitNoTrim) {
	std::vector<std::string> ref;
	ref.push_back("abcd efgh");
	EXPECT_EQ(ref, split("abcd efgh", ';', false));
}

TEST_F(StringTests,
SplitNothingToSplitWithTrim) {
	std::vector<std::string> ref;
	ref.push_back("abcd efgh");
	EXPECT_EQ(ref, split("abcd efgh", ';', true));
}

TEST_F(StringTests,
SplitSplitsCorrectlyInOnePlaceNoTrim) {
	std::vector<std::string> ref;
	ref.push_back("\n abcd ");
	ref.push_back(" ef gh \t ");
	EXPECT_EQ(ref, split("\n abcd ; ef gh \t ", ';', false));
}

TEST_F(StringTests,
SplitSplitsCorrectlyInOnePlaceWithTrim) {
	std::vector<std::string> ref;
	ref.push_back("abcd");
	ref.push_back("ef gh");
	EXPECT_EQ(ref, split("\n abcd ; ef gh \t ", ';', true));
}

TEST_F(StringTests,
SplitSplitsCorrectlyInTwoPlacesNoTrim) {
	std::vector<std::string> ref;
	ref.push_back("\n abcd ");
	ref.push_back(" ef gh \t ");
	ref.push_back(" CCC");
	EXPECT_EQ(ref, split("\n abcd ; ef gh \t ; CCC", ';', false));
}

TEST_F(StringTests,
SplitSplitsCorrectlyInTwoPlacesWithTrim) {
	std::vector<std::string> ref;
	ref.push_back("abcd");
	ref.push_back("ef gh");
	ref.push_back("CCC");
	EXPECT_EQ(ref, split("\n abcd ; ef gh \t ; CCC", ';', true));
}

TEST_F(StringTests,
SplitSplitsCorrectlyWhenSeparatorIsAtTheBeginningOfString) {
	std::vector<std::string> ref;
	ref.push_back("");
	ref.push_back("abcd");
	EXPECT_EQ(ref, split(";abcd", ';', true));
}

TEST_F(StringTests,
SplitSplitsCorrectlyWhenSeparatorIsAtTheEndOfString) {
	std::vector<std::string> ref;
	ref.push_back("abcd");
	ref.push_back("");
	EXPECT_EQ(ref, split("abcd;", ';', true));
}

TEST_F(StringTests,
SplitSplitsCorrectlyWhenThereAreJustSeparators) {
	std::vector<std::string> ref;
	ref.push_back("");
	ref.push_back("");
	ref.push_back("");
	EXPECT_EQ(ref, split(";;", ';', true));
	EXPECT_EQ(ref, split(" ; ; ", ';', true));
}

//
// unifyLineEnds()
//

TEST_F(StringTests,
UnifyLineEndsReturnsOriginalStringWhenThereAreNoLineEnds) {
	EXPECT_EQ("abcd", unifyLineEnds("abcd"));
}

TEST_F(StringTests,
UnifyLineEndsReturnsOriginalStringWhenThereAreLFLineEnds) {
	EXPECT_EQ("\n\n", unifyLineEnds("\n\n"));
}

TEST_F(StringTests,
UnifyLineEndsConvertsCRLFToLF) {
	EXPECT_EQ("\n\n", unifyLineEnds("\r\n\r\n"));
}

TEST_F(StringTests,
UnifyLineEndsConvertsCRToLF) {
	EXPECT_EQ("\n\n", unifyLineEnds("\r\r"));
}

//
// joinStrings()
//

TEST_F(StringTests,
JoinStringsEmptyVector) {
	EXPECT_EQ("", joinStrings(std::vector<std::string>(), ""));
	EXPECT_EQ("", joinStrings(std::vector<std::string>(), ";"));
	EXPECT_EQ("", joinStrings(std::vector<std::string>(), "XXX"));
}

TEST_F(StringTests,
JoinStringsOneItemVector) {
	std::vector<std::string> strings;
	strings.push_back("test");
	EXPECT_EQ("test", joinStrings(strings, ""));
	EXPECT_EQ("test", joinStrings(strings, ";"));
	EXPECT_EQ("test", joinStrings(strings, "XXX"));
}

TEST_F(StringTests,
JoinStringsTwoItemsVector) {
	std::vector<std::string> strings;
	strings.push_back("abc");
	strings.push_back("efg");
	EXPECT_EQ("abcefg", joinStrings(strings, ""));
	EXPECT_EQ("abc;efg", joinStrings(strings, ";"));
	EXPECT_EQ("abcXXXefg", joinStrings(strings, "XXX"));
}

TEST_F(StringTests,
JoinStringsThreeItemsVectorEmptySeparator) {
	std::vector<std::string> strings;
	strings.push_back("abc");
	strings.push_back("efg");
	strings.push_back(" ijK ");
	EXPECT_EQ("abcefg ijK ", joinStrings(strings, ""));
	EXPECT_EQ("abc;efg; ijK ", joinStrings(strings, ";"));
	EXPECT_EQ("abcXXXefgXXX ijK ", joinStrings(strings, "XXX"));
}

TEST_F(StringTests,
JoinStringsEmptySet) {
	EXPECT_EQ("", joinStrings(std::set<std::string>(), ""));
	EXPECT_EQ("", joinStrings(std::set<std::string>(), ";"));
	EXPECT_EQ("", joinStrings(std::set<std::string>(), "XXX"));
}

TEST_F(StringTests,
JoinStringsOneItemSet) {
	std::set<std::string> strings;
	strings.insert("test");
	EXPECT_EQ("test", joinStrings(strings, ""));
	EXPECT_EQ("test", joinStrings(strings, ";"));
	EXPECT_EQ("test", joinStrings(strings, "XXX"));
}

TEST_F(StringTests,
JoinStringsTwoItemsSet) {
	std::set<std::string> strings;
	strings.insert("abc");
	strings.insert("efg");
	// We assume that std::set<> is implemented as a tree and ordered
	// lexicographically, which is a typical C++ implementation.
	EXPECT_EQ("abcefg", joinStrings(strings, ""));
	EXPECT_EQ("abc;efg", joinStrings(strings, ";"));
	EXPECT_EQ("abcXXXefg", joinStrings(strings, "XXX"));
}

TEST_F(StringTests,
JoinStringsThreeItemsSetEmptySeparator) {
	std::set<std::string> strings;
	strings.insert("abc");
	strings.insert("efg");
	strings.insert("ijK ");
	// We assume that std::set<> is implemented as a tree and ordered
	// lexicographically, which is a typical C++ implementation.
	EXPECT_EQ("abcefgijK ", joinStrings(strings, ""));
	EXPECT_EQ("abc;efg;ijK ", joinStrings(strings, ";"));
	EXPECT_EQ("abcXXXefgXXXijK ", joinStrings(strings, "XXX"));
}

//
// startsWith()
//

TEST_F(StringTests,
StartsWithStarts) {
	EXPECT_TRUE(startsWith("", ""));
	EXPECT_TRUE(startsWith("a", ""));
	EXPECT_TRUE(startsWith("a", "a"));
	EXPECT_TRUE(startsWith(" C", ""));
	EXPECT_TRUE(startsWith("  X", " "));
	EXPECT_TRUE(startsWith("abcDEF", "abc"));
}

TEST_F(StringTests,
StartsWithDoesNotStart) {
	EXPECT_FALSE(startsWith("", "a"));
	EXPECT_FALSE(startsWith("b", "c"));
	EXPECT_FALSE(startsWith("  X", " X"));
	EXPECT_FALSE(startsWith("abcDEF", "abd"));
}

TEST_F(StringTests,
CanBeCalledWithEitherCharStarOrStdStringLiteral) {
	EXPECT_TRUE(startsWith("abc", "abc"));
	EXPECT_TRUE(startsWith("abc", "abc"s));
}

//
// endsWith()
//

TEST_F(StringTests,
EndsWithEnds) {
	EXPECT_TRUE(endsWith("", ""));
	EXPECT_TRUE(endsWith("a", ""));
	EXPECT_TRUE(endsWith("a", "a"));
	EXPECT_TRUE(endsWith(" C", ""));
	EXPECT_TRUE(endsWith("X  ", " "));
	EXPECT_TRUE(endsWith("abcDEF", "DEF"));
}

TEST_F(StringTests,
EndsWithDoesNotEnd) {
	EXPECT_FALSE(endsWith("", "a"));
	EXPECT_FALSE(endsWith("b", "c"));
	EXPECT_FALSE(endsWith("X  ", "X "));
	EXPECT_FALSE(endsWith("abcDEF", "DEG"));
}

//
// hasSubstringOnPosition()
//

TEST_F(StringTests,
HasSubstringOnPositionTrue) {
	EXPECT_TRUE(hasSubstringOnPosition("a", "a", 0));
	EXPECT_TRUE(hasSubstringOnPosition(" C", " ", 0));
	EXPECT_TRUE(hasSubstringOnPosition("X  ", " ", 2));
	EXPECT_TRUE(hasSubstringOnPosition("abcDEF", "DEF", 3));
}

TEST_F(StringTests,
HasSubstringOnPositionFalse) {
	EXPECT_FALSE(hasSubstringOnPosition("a", "a", 1));
	EXPECT_FALSE(hasSubstringOnPosition(" C", " ", 20));
	EXPECT_FALSE(hasSubstringOnPosition("X  ", "xAxAxAx", 2));
	EXPECT_FALSE(hasSubstringOnPosition("abcDEF", "DEFA", 3));
}

//
// hasSubstringInArea()
//

TEST_F(StringTests,
HasSubstringInAreaTrue) {
	EXPECT_TRUE(hasSubstringInArea("0", "", 0, 0));
	EXPECT_TRUE(hasSubstringInArea("0123", "01", 0, 1));
	EXPECT_TRUE(hasSubstringInArea("0123456789", "0123456789", 0, 9));
	EXPECT_TRUE(hasSubstringInArea("0123456789", "12345678", 0, 8));
	EXPECT_TRUE(hasSubstringInArea("0123456789", "12345678", 1, 8));
}

TEST_F(StringTests,
HasSubstringInAreaFalse) {
	EXPECT_FALSE(hasSubstringInArea("0123456789", "0123456789", 0, 8));
}

//
// isComposedOnlyOfChars()
//

TEST_F(StringTests,
IsComposedOnlyOfCharsEmptyStringIsComposedOnlyOfAnything) {
	EXPECT_TRUE(isComposedOnlyOfChars("", "abcd"));
	EXPECT_TRUE(isComposedOnlyOfChars("", "012345"));
	EXPECT_TRUE(isComposedOnlyOfChars("", 'a'));
}

TEST_F(StringTests,
IsComposedOnlyOfCharsAnyStringIsNotComposedOnlyOfNoCharacters) {
	EXPECT_FALSE(isComposedOnlyOfChars("abcd", ""));
}

TEST_F(StringTests,
IsComposedOnlyOfCharsIsComposed) {
	EXPECT_TRUE(isComposedOnlyOfChars("aaa", 'a'));
	EXPECT_TRUE(isComposedOnlyOfChars("aaa", "a"));
	EXPECT_TRUE(isComposedOnlyOfChars("aaba", "ba"));
}

TEST_F(StringTests,
IsComposedOnlyOfCharsIsNotComposed) {
	EXPECT_FALSE(isComposedOnlyOfChars("abcde", 'a'));
	EXPECT_FALSE(isComposedOnlyOfChars("abcde", "abc"));
	EXPECT_FALSE(isComposedOnlyOfChars("012345", "012346"));
}

//
// isComposedOnlyOfStrings()
//

TEST_F(StringTests,
IsComposedOnlyOfStringsEmptyStringIsComposedOnlyOfEmptyString) {
	EXPECT_TRUE(isComposedOnlyOfStrings("", ""));
	EXPECT_FALSE(isComposedOnlyOfStrings("", "a"));
	EXPECT_FALSE(isComposedOnlyOfStrings("", "012345"));
}

TEST_F(StringTests,
IsComposedOnlyOfStringsAnyNonEmptyStringIsNotComposedOnlyOfEmptyString) {
	EXPECT_FALSE(isComposedOnlyOfStrings("a", ""));
	EXPECT_FALSE(isComposedOnlyOfStrings("abcd", ""));
}

TEST_F(StringTests,
IsComposedOnlyOfStringsIsComposed) {
	EXPECT_TRUE(isComposedOnlyOfStrings("abcd",   "abcd"));
	EXPECT_TRUE(isComposedOnlyOfStrings("ababab", "ab"));
	EXPECT_TRUE(isComposedOnlyOfStrings("aaaaa",  "aa"));
}

TEST_F(StringTests,
IsComposedOnlyOfStringsIsNotComposed) {
	EXPECT_FALSE(isComposedOnlyOfStrings("ababab", "ba"));
}

//
// stripDirs()
//

TEST_F(StringTests,
StripDirsStripsAbsoluteUnixPaths) {
	EXPECT_EQ("test.c", stripDirs("/home/user/test.c"));
}

TEST_F(StringTests,
StripDirsDoesNothingWhenFilenameIsProvided) {
	EXPECT_EQ("test.c", stripDirs("test.c"));
}

TEST_F(StringTests,
StripDirsStripsAbsoluteWindowsPathUsingSlashes) {
	EXPECT_EQ("test.c", stripDirs("C:/home/user/test.c"));
}

//
// replaceAll()
//

TEST_F(StringTests,
ReplaceAllWhenFromIsEmptyOriginalStringIsReturned) {
	EXPECT_EQ("abcd", replaceAll("abcd", "", ""));
	EXPECT_EQ("abcd", replaceAll("abcd", "", "aa"));
}

TEST_F(StringTests,
ReplaceAllNothingToBeReplaceInEmptyString) {
	EXPECT_EQ("", replaceAll("", "aa", ""));
	EXPECT_EQ("", replaceAll("", "aa", "aa"));
}

TEST_F(StringTests,
ReplaceAllReplaceWholeString) {
	EXPECT_EQ("", replaceAll("abcd", "abcd", ""));
	EXPECT_EQ("xyxy", replaceAll("abcd", "abcd", "xyxy"));
}

TEST_F(StringTests,
ReplaceAllOnlySingleOccurrence) {
	EXPECT_EQ("Axyxy", replaceAll("Aabcd", "abcd", "xyxy"));
	EXPECT_EQ("xyxyB", replaceAll("abcdB", "abcd", "xyxy"));
	EXPECT_EQ("AxyxyB", replaceAll("AabcdB", "abcd", "xyxy"));
}

TEST_F(StringTests,
ReplaceAllManyOccurrences) {
	EXPECT_EQ("yAyAyAy", replaceAll("xAxAxAx", "x", "y"));
	EXPECT_EQ("AAA", replaceAll("xAxAxAx", "x", ""));
	EXPECT_EQ("", replaceAll("xxxx", "x", ""));
}

TEST_F(StringTests,
ReplaceAllNoOccurrences) {
	EXPECT_EQ("abcdefgh", replaceAll("abcdefgh", "x", "y"));
}

//
// removeWhitespace()
//

TEST_F(StringTests,
RemoveWhitespaceCorrectResults) {
	EXPECT_EQ("", removeWhitespace(""));
	EXPECT_EQ("", removeWhitespace("   "));
	EXPECT_EQ("", removeWhitespace("\t"));
	EXPECT_EQ("", removeWhitespace("\n"));
	EXPECT_EQ("", removeWhitespace(" \t \n  \t \n  "));
	EXPECT_EQ("abc", removeWhitespace("  a \t b \n c  "));
	EXPECT_EQ("abc", removeWhitespace("abc"));
}

//
// replaceNonprintableChars()
//

TEST_F(StringTests,
ReplaceNonprintableCharsDoesNothingWhenThereAreNoNonprintableChars) {
	EXPECT_EQ("", replaceNonprintableChars(""));
	EXPECT_EQ("abc def", replaceNonprintableChars("abc def"));
}

TEST_F(StringTests,
ReplaceNonprintableCharsReplacesNonprintableCharsWithTheirHexadecimalValues) {
	EXPECT_EQ("X\\x1cY\\x1dZ", replaceNonprintableChars("X\x1cY\x1dZ"));
}

TEST_F(StringTests,
ReplaceNonprintableCharsEnsuresThatHexadecimalValuesAreTwoCharsLong) {
	EXPECT_EQ("\\x00", replaceNonprintableChars("\0"s));
}

//
// replaceNonasciiChars()
//

TEST_F(StringTests,
ReplaceNonasciiCharsDoesNothingWhenThereAreNoNonasciiChars) {
	EXPECT_EQ("", replaceNonasciiChars(""));
	EXPECT_EQ("abc def", replaceNonasciiChars("abc def"));
}

TEST_F(StringTests,
ReplaceNonasciiCharsReplacesNonasciiCharsWithTheirHexadecimalValues) {
	EXPECT_EQ("X\\xacY\\xadZ", replaceNonasciiChars("X\xacY\xadZ"));
}

TEST_F(StringTests,
ReplaceNonasciiCharsEnsuresThatHexadecimalValuesAreTwoCharsLong) {
	EXPECT_EQ("\\x80", replaceNonprintableChars("\x80"s));
}

//
// replaceNonalnumCharsWith()
//

TEST_F(StringTests,
ReplaceNonalnumCharsWithUnderscore) {
	EXPECT_EQ("", replaceNonalnumCharsWith("", '_'));
	EXPECT_EQ("__", replaceNonalnumCharsWith("__", '_'));
	EXPECT_EQ("7za", replaceNonalnumCharsWith("7za", '_'));
	EXPECT_EQ("Mach_O", replaceNonalnumCharsWith("Mach-O", '_'));
}

//
// getLineAndColumnFromPosition()
//
TEST_F(StringTests,
GetLineAndColumnFromPositionTransformsPositionsIntoLinesAndColumns) {

	std::pair<std::size_t, std::size_t> a{0,0};
	EXPECT_EQ(a, getLineAndColumnFromPosition("", 0));

	std::pair<std::size_t, std::size_t> b{1,1};
	EXPECT_EQ(b, getLineAndColumnFromPosition("abc", 0));

	std::pair<std::size_t, std::size_t> c{1,3};
	EXPECT_EQ(c, getLineAndColumnFromPosition("abc", 2));

	std::pair<std::size_t, std::size_t> d{0,0};
	EXPECT_EQ(d, getLineAndColumnFromPosition("abc", 3));

	std::pair<std::size_t, std::size_t> e{2,2};
	EXPECT_EQ(e, getLineAndColumnFromPosition("abc\ndef", 5));
}

//
// isNumber()
//

TEST_F(StringTests,
isNumberAcceptsNumbers) {
	EXPECT_TRUE(isNumber("0"));
	EXPECT_TRUE(isNumber("1"));
	EXPECT_TRUE(isNumber("+1"));
	EXPECT_TRUE(isNumber("-1"));
	EXPECT_TRUE(isNumber("123"));
	EXPECT_TRUE(isNumber("+123"));
	EXPECT_TRUE(isNumber("-123"));
}

TEST_F(StringTests,
isNumberRejectsNonNumbers) {
	EXPECT_FALSE(isNumber("a"));
	EXPECT_FALSE(isNumber("+a"));
	EXPECT_FALSE(isNumber("-a"));
	EXPECT_FALSE(isNumber("abc"));
	EXPECT_FALSE(isNumber("a12"));
	EXPECT_FALSE(isNumber("12a"));
	EXPECT_FALSE(isNumber("1a2"));
}

//
// isIdentifier()
//

TEST_F(StringTests,
isIdentifierAcceptValidIds) {
	EXPECT_TRUE(isIdentifier("_ymbol"));
	EXPECT_TRUE(isIdentifier("symBOL"));
	EXPECT_TRUE(isIdentifier("sym80L"));
	EXPECT_TRUE(isIdentifier("__m___"));
	EXPECT_TRUE(isIdentifier("symbol"));
	EXPECT_TRUE(isIdentifier("SYMBOL"));
}

TEST_F(StringTests,
isIdentifierRejectsInvalidIds) {
	EXPECT_FALSE(isIdentifier("0_symbo"));
	EXPECT_FALSE(isIdentifier("0symbol"));
	EXPECT_FALSE(isIdentifier("%symBOL"));
	EXPECT_FALSE(isIdentifier("sym&80L"));
	EXPECT_FALSE(isIdentifier("__m_*_)"));
	EXPECT_FALSE(isIdentifier("5466421"));
	EXPECT_FALSE(isIdentifier(""));
}

//
// isPrintable()
//

TEST_F(StringTests,
isPrintableAccept) {
	EXPECT_TRUE(isPrintable("abcd468445efs1f"));
	EXPECT_TRUE(isPrintable("!@#$%^&*{}-+|/"));
	EXPECT_TRUE(isPrintable(""));
}

TEST_F(StringTests,
isPrintableReject) {
	EXPECT_FALSE(isPrintable("abcd468445 \n efs1f"));
	EXPECT_FALSE(isPrintable("!@#$%^&*{}-+|/\r"));
	EXPECT_FALSE(isPrintable("\n"));
}

//
// removeLeadingCharacter()
//

TEST_F(StringTests,
removeLeadingCharacterRemovesAllMatchingLeadingCharacters) {
	EXPECT_EQ("abc", removeLeadingCharacter("_abc", '_'));
	EXPECT_EQ("abc", removeLeadingCharacter("__abc", '_'));
	EXPECT_EQ("abc", removeLeadingCharacter("____abc", '_'));

	EXPECT_EQ("abc", removeLeadingCharacter("1111abc", '1'));
	EXPECT_EQ("abc", removeLeadingCharacter("&&&&abc", '&'));
	EXPECT_EQ("abc", removeLeadingCharacter("xxxxabc", 'x'));
}

TEST_F(StringTests,
removeLeadingCharacterDoesNothingIfThereAreNoSpecifiedLeadingCharacters) {
	EXPECT_EQ("abc", removeLeadingCharacter("abc", '_'));
	EXPECT_EQ("a_b_c_", removeLeadingCharacter("a_b_c_", '_'));
	EXPECT_EQ("abc", removeLeadingCharacter("abc", 'x'));
	EXPECT_EQ("abc", removeLeadingCharacter("abc", '&'));
}

TEST_F(StringTests,
removeLeadingCharacterRemovesOnlySpecifiedNumberOfCharacters) {
	EXPECT_EQ("___abc", removeLeadingCharacter("___abc", '_', 0));
	EXPECT_EQ("__abc", removeLeadingCharacter("___abc", '_', 1));
	EXPECT_EQ("_abc", removeLeadingCharacter("___abc", '_', 2));
	EXPECT_EQ("abc", removeLeadingCharacter("___abc", '_', 3));
	EXPECT_EQ("abc", removeLeadingCharacter("___abc", '_', 4));
}

//
// isContolCharacter()
//

TEST_F(StringTests,
isContolCharacterCorrectlyDecidesForControlAndNonControlChars) {
	EXPECT_TRUE(isContolCharacter('\b'));
	EXPECT_TRUE(isContolCharacter('\f'));
	EXPECT_TRUE(isContolCharacter('\n'));
	EXPECT_TRUE(isContolCharacter('\r'));
	EXPECT_TRUE(isContolCharacter('\t'));
	EXPECT_TRUE(isContolCharacter('\v'));

	EXPECT_FALSE(isContolCharacter('a'));
	EXPECT_FALSE(isContolCharacter('z'));
	EXPECT_FALSE(isContolCharacter('A'));
	EXPECT_FALSE(isContolCharacter('Z'));
	EXPECT_FALSE(isContolCharacter('0'));
	EXPECT_FALSE(isContolCharacter('9'));
	EXPECT_FALSE(isContolCharacter(0));
	EXPECT_FALSE(isContolCharacter(5));
	EXPECT_FALSE(isContolCharacter(17));
	EXPECT_FALSE(isContolCharacter(29));
	EXPECT_FALSE(isContolCharacter(127));
}

//
// isNiceCharacter()
//

TEST_F(StringTests,
isNiceCharacterCorrectlyDecidesForNiceAndNonNiceChars) {
	EXPECT_TRUE(isNiceCharacter(' '));
	EXPECT_TRUE(isNiceCharacter('!'));
	EXPECT_TRUE(isNiceCharacter('"'));
	EXPECT_TRUE(isNiceCharacter('/'));
	EXPECT_TRUE(isNiceCharacter('0'));
	EXPECT_TRUE(isNiceCharacter('9'));
	EXPECT_TRUE(isNiceCharacter(':'));
	EXPECT_TRUE(isNiceCharacter('@'));
	EXPECT_TRUE(isNiceCharacter('A'));
	EXPECT_TRUE(isNiceCharacter('Z'));
	EXPECT_TRUE(isNiceCharacter('['));
	EXPECT_TRUE(isNiceCharacter('`'));
	EXPECT_TRUE(isNiceCharacter('a'));
	EXPECT_TRUE(isNiceCharacter('z'));
	EXPECT_TRUE(isNiceCharacter('{'));
	EXPECT_TRUE(isNiceCharacter('~'));

	EXPECT_TRUE(isNiceCharacter('\b'));
	EXPECT_TRUE(isNiceCharacter('\f'));
	EXPECT_TRUE(isNiceCharacter('\n'));
	EXPECT_TRUE(isNiceCharacter('\r'));
	EXPECT_TRUE(isNiceCharacter('\t'));
	EXPECT_TRUE(isNiceCharacter('\v'));

	EXPECT_FALSE(isNiceCharacter(0));
	EXPECT_FALSE(isNiceCharacter(5));
	EXPECT_FALSE(isNiceCharacter(17));
	EXPECT_FALSE(isNiceCharacter(29));
	EXPECT_FALSE(isNiceCharacter(127));
}

//
// isNiceString()
//

TEST_F(StringTests,
IsNiceStringCorrectlyDecidesForDefaultRation) {
	EXPECT_TRUE(isNiceString("a"));
	EXPECT_TRUE(isNiceString("ab"));
	EXPECT_TRUE(isNiceString("ab\x01"));
	EXPECT_TRUE(isNiceString("abcd"));
	EXPECT_TRUE(isNiceString("abcd\x01\x02"));
	EXPECT_TRUE(isNiceString("ab\t\n"));
	EXPECT_TRUE(isNiceString("\t\n"));
	EXPECT_TRUE(isNiceString("a\x00"s));

	EXPECT_FALSE(isNiceString(""));
	EXPECT_FALSE(isNiceString("\x01"));
	EXPECT_FALSE(isNiceString("a\x01"));
	EXPECT_FALSE(isNiceString("ab\x01\x02"));
	EXPECT_FALSE(isNiceString("abcd\x01\x02\x03"));
}

TEST_F(StringTests,
IsNiceStringCorrectlyDecidesForCustomRation) {
	EXPECT_TRUE(isNiceString("abcdef", 1.0));
	EXPECT_FALSE(isNiceString("abcdef\x01", 1.0));

	EXPECT_TRUE(isNiceString("\x01", 0.0));
	EXPECT_TRUE(isNiceString("abcdef\x01", 0.0));
	EXPECT_FALSE(isNiceString("", 0.0));

	EXPECT_TRUE(isNiceString("ab\x01\x02", 0.5));
	EXPECT_FALSE(isNiceString("ab\x01\x02\x03", 0.5));
}

//
// isNiceAsciiWideCharacter()
//

TEST_F(StringTests,
isNiceAsciiWideCharacterCorrectlyDecidesForNiceAndNonNiceChars) {
	EXPECT_TRUE(isNiceAsciiWideCharacter(' '));
	EXPECT_TRUE(isNiceAsciiWideCharacter('!'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('"'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('/'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('0'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('9'));
	EXPECT_TRUE(isNiceAsciiWideCharacter(':'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('@'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('A'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('Z'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('['));
	EXPECT_TRUE(isNiceAsciiWideCharacter('`'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('a'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('z'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('{'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('~'));

	EXPECT_TRUE(isNiceAsciiWideCharacter('\b'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('\f'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('\n'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('\r'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('\t'));
	EXPECT_TRUE(isNiceAsciiWideCharacter('\v'));

	EXPECT_FALSE(isNiceAsciiWideCharacter(0));
	EXPECT_FALSE(isNiceAsciiWideCharacter(5));
	EXPECT_FALSE(isNiceAsciiWideCharacter(17));
	EXPECT_FALSE(isNiceAsciiWideCharacter(29));
	EXPECT_FALSE(isNiceAsciiWideCharacter(127));
	EXPECT_FALSE(isNiceAsciiWideCharacter(200));
	EXPECT_FALSE(isNiceAsciiWideCharacter(1000));
	EXPECT_FALSE(isNiceAsciiWideCharacter(10000));
}

//
// isNiceAsciiWideString()
//

TEST_F(StringTests,
isNiceAsciiWideStringCorrectlyDecidesForDefaultRatio) {
	std::vector<unsigned long long> s1 = {'a', 'b', 'c', 'd'};
	EXPECT_TRUE(isNiceAsciiWideString(s1));

	std::vector<unsigned long long> s2 = {'@', 'b', '/', '+'};
	EXPECT_TRUE(isNiceAsciiWideString(s2));

	std::vector<unsigned long long> s3 = {'\t', 'b', '\\', '\n'};
	EXPECT_TRUE(isNiceAsciiWideString(s3));

	std::vector<unsigned long long> s4;
	EXPECT_FALSE(isNiceAsciiWideString(s4));

	std::vector<unsigned long long> s5 = {0};
	EXPECT_FALSE(isNiceAsciiWideString(s5));

	std::vector<unsigned long long> s6 = {'a', 'b', 'c', 156};
	EXPECT_FALSE(isNiceAsciiWideString(s6));

	std::vector<unsigned long long> s7 = {1, 2, 3, 4};
	EXPECT_FALSE(isNiceAsciiWideString(s7));

	std::vector<unsigned long long> s8 = {'a', 'b', 123, 12345, 123456};
	EXPECT_FALSE(isNiceAsciiWideString(s8));
}

TEST_F(StringTests,
isNiceAsciiWideStringCorrectlyDecidesForCustomRatio) {
	std::vector<unsigned long long> s1 = {'a', 'b', 'c', 1234};
	EXPECT_TRUE(isNiceAsciiWideString(s1, 0.75));
	EXPECT_FALSE(isNiceAsciiWideString(s1, 0.8));

	std::vector<unsigned long long> s2 = {'a', 'b', 1234, 12345};
	EXPECT_TRUE(isNiceAsciiWideString(s2, 0.5));
	EXPECT_FALSE(isNiceAsciiWideString(s2, 0.75));

	std::vector<unsigned long long> s3 = {1, 2, 1234, 12345};
	EXPECT_TRUE(isNiceAsciiWideString(s3, 0.0));
	EXPECT_FALSE(isNiceAsciiWideString(s3, 0.1));
}

//
// getIndentation()
//

TEST_F(StringTests,
GetIndentationReturnsCorrectStringForDefaultCharacter) {
	EXPECT_EQ("", getIndentation(0));
	EXPECT_EQ("\t", getIndentation(1));
	EXPECT_EQ("\t\t\t\t\t", getIndentation(5));
}

TEST_F(StringTests,
GetIndentationReturnsCorrectStringForCustomCharacter) {
	EXPECT_EQ("", getIndentation(0, ' '));
	EXPECT_EQ(" ", getIndentation(1, ' '));
	EXPECT_EQ("     ", getIndentation(5, ' '));
}

//
// appendHex()
//

TEST_F(StringTests,
appendHexAddsHexSuffix) {
	std::string s = "object";
	appendHex(s, 0x1234);
	EXPECT_EQ("object_1234", s);
}

//
// appendDec()
//

TEST_F(StringTests,
appendDecAddsDecSuffix) {
	std::string s = "object";
	appendDec(s, 1234);
	EXPECT_EQ("object_1234", s);
}

//
// appendHexRet()
//

TEST_F(StringTests,
appendHexRetAddsHexSuffix) {
	EXPECT_EQ("object_1234", appendHexRet("object", 0x1234));
}

//
// appendDecRet()
//

TEST_F(StringTests,
appendDecRetAddsHexSuffix) {
	EXPECT_EQ("object_1234", appendDecRet("object", 1234));
}

//
// removeSuffix()
//

TEST_F(StringTests,
removeSuffixRemovesSpecifiedSuffix) {
	std::string s = "object_1234";
	removeSuffix(s);
	EXPECT_EQ("object", s);

	s = "object_1234";
	removeSuffix(s, "_12");
	EXPECT_EQ("object", s);

	s = "object=1234";
	removeSuffix(s, "=");
	EXPECT_EQ("object", s);

	s = "object===1234";
	removeSuffix(s, "===");
	EXPECT_EQ("object", s);
}

TEST_F(StringTests,
removeSuffixDoesNothingWhenSuffixNotFound) {
	std::string s = "object-1234";
	removeSuffix(s);
	EXPECT_EQ("object-1234", s);

	s = "object_1234";
	removeSuffix(s, "=");
	EXPECT_EQ("object_1234", s);
}

//
// removeSuffixRet()
//

TEST_F(StringTests,
removeSuffixRetRemovesSpecifiedSuffix) {
	EXPECT_EQ("object", removeSuffixRet("object_1234"));
	EXPECT_EQ("object", removeSuffixRet("object_1234", "_12"));
	EXPECT_EQ("object", removeSuffixRet("object=1234", "="));
	EXPECT_EQ("object", removeSuffixRet("object===1234", "==="));
}

TEST_F(StringTests,
removeSuffixRetDoesNothingWhenSuffixNotFound) {
	EXPECT_EQ("object-1234", removeSuffixRet("object-1234"));
	EXPECT_EQ("object_1234", removeSuffixRet("object_1234", "="));
}

//
// toHexString()
//

TEST_F(StringTests,
toHexStringSuccess) {
	EXPECT_EQ("0", toHexString(0x0));
	EXPECT_EQ("123456789abcdef", toHexString(0x123456789abcdef));
}

//
// normalizeName()
//

TEST_F(StringTests,
normalizeNameSuccess) {
	EXPECT_EQ("", normalizeName(""));
	EXPECT_EQ("_lt_", normalizeName("<"));
	EXPECT_EQ("_gt_", normalizeName(">"));
	EXPECT_EQ("_lsb_", normalizeName("["));
	EXPECT_EQ("_rsb_", normalizeName("]"));
	EXPECT_EQ("_lb_", normalizeName("("));
	EXPECT_EQ("_rb_", normalizeName(")"));
	EXPECT_EQ("_comma_", normalizeName(","));
	EXPECT_EQ("_destructor_", normalizeName("~"));
	EXPECT_EQ("_ptr_", normalizeName("*"));
	EXPECT_EQ("_ampersand_", normalizeName("&"));
	EXPECT_EQ("_eq_", normalizeName("="));
	EXPECT_EQ("_not_", normalizeName("!"));
	EXPECT_EQ("_qm_", normalizeName("?"));
	EXPECT_EQ("_______", normalizeName(" `\\@:\n\r"));
	EXPECT_EQ(".", normalizeName("."));
	EXPECT_EQ("abcd1234", normalizeName("abcd1234"));
	EXPECT_EQ("_1abc", normalizeName("1abc"));
}

//
// findFirstInEmbeddedLists()
//

TEST_F(StringTests,
findFirstInEmbeddedListsReturnsNposIfNotFound) {
	size_t pos = 0;

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "", ',', {}));
	EXPECT_EQ(std::string::npos, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "abcdef", ',', {}));
	EXPECT_EQ(std::string::npos, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "{ab,cd,ef}", ',', { {'{','}'} }));
	EXPECT_EQ(std::string::npos, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "{a,b}cd(e,f)", ',', { {'{','}'}, {'(',')'} }));
	EXPECT_EQ(std::string::npos, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "{{a,b},(c,{d}),(e,f)}", ',', { {'{','}'}, {'(',')'} }));
	EXPECT_EQ(std::string::npos, pos);
}

TEST_F(StringTests,
findFirstInEmbeddedListsReturnsFirstOkOccurrence) {
	size_t pos = 0;

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, ",", ',', {}));
	EXPECT_EQ(0, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "ab,cd,ef", ',', {}));
	EXPECT_EQ(2, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "{ab,cd},(ef)", ',', { {'{','}'}, {'(',')'} }));
	EXPECT_EQ(7, pos);

	EXPECT_FALSE(findFirstInEmbeddedLists(pos, "{{(a,b)},(c),d},(ef)", ',', { {'{','}'}, {'(',')'} }));
	EXPECT_EQ(15, pos);
}

TEST_F(StringTests,
findFirstInEmbeddedListsReturnsTrueIfListMalformedPosIsNotChanged) {
	size_t pos = 123;

	EXPECT_TRUE(findFirstInEmbeddedLists(pos, "{{ab},cd", ',', { {'{','}'} }));
	EXPECT_EQ(123, pos);

	EXPECT_TRUE(findFirstInEmbeddedLists(pos, "{{a(b)},(c},d", ',', { {'{','}'}, {'(',')'} }));
	EXPECT_EQ(123, pos);
}

//
// removeConsecutiveSpaces()
//

TEST_F(StringTests,
removeConsecutiveSpacesRemovesSpaces) {
	EXPECT_EQ(
			"I Like StackOverflow a lot",
			removeConsecutiveSpaces("I    Like    StackOverflow a      lot"));
}

//
// asEscapedCString()
//

TEST_F(StringTests,
AsEscapedCStringReturnsSameStringFor8BitTextStringWithoutSpecialCharacters) {
	ASSERT_EQ("test", asEscapedCString({'t', 'e', 's', 't'}, 8));
}

TEST_F(StringTests,
AsEscapedCStringReturnsCorrectlyEscapedStringFor8BitTextStringWithSpecialCharacters) {
	// Based on http://en.cppreference.com/w/c/language/escape
	ASSERT_EQ("\\\"", asEscapedCString({'\"'}, 8));
	ASSERT_EQ("\\\\", asEscapedCString({'\\'}, 8));
	ASSERT_EQ("\\a", asEscapedCString({'\a'}, 8));
	ASSERT_EQ("\\b", asEscapedCString({'\b'}, 8));
	ASSERT_EQ("\\f", asEscapedCString({'\f'}, 8));
	ASSERT_EQ("\\n", asEscapedCString({'\n'}, 8));
	ASSERT_EQ("\\r", asEscapedCString({'\r'}, 8));
	ASSERT_EQ("\\t", asEscapedCString({'\t'}, 8));
	ASSERT_EQ("\\v", asEscapedCString({'\v'}, 8));

	// Although the following characters can be written as escape sequences
	// (see the link above), we generate them normally because it is more
	// readable.
	ASSERT_EQ("'", asEscapedCString({'\''}, 8));
	ASSERT_EQ("?", asEscapedCString({'\?'}, 8));
}

TEST_F(StringTests,
AsEscapedCStringReturnsCorrectlyEscapedStringFor8BitBinaryString) {
	ASSERT_EQ(
		"\\x01\\x02\\x03\\x04\\xff",
		asEscapedCString({1, 2, 3, 4, std::numeric_limits<std::uint8_t>::max()}, 8)
	);
}

TEST_F(StringTests,
AsEscapedCStringReturnsCorrectlyEscapedStringForBinaryWideStringWith16BitCharSize) {
	ASSERT_EQ(
		"\\x0001\\x0002\\x0003\\x0004\\xffff",
		asEscapedCString({1, 2, 3, 4, std::numeric_limits<std::uint16_t>::max()}, 16)
	);
}

TEST_F(StringTests,
AsEscapedCStringReturnsCorrectlyEscapedStringForBinaryWideStringWith32BitCharSize) {
	ASSERT_EQ(
		"\\x00000001\\x00000002\\x00000003\\x00000004\\xffffffff",
		asEscapedCString({1, 2, 3, 4, std::numeric_limits<std::uint32_t>::max()}, 32)
	);
}

TEST_F(StringTests,
AsEscapedCStringDoesNotEscapeAllCharsWhenOnlyNonPrintableCharsAreNullBytes) {
	ASSERT_EQ(
		"zz\\x00zz\\x00zz"s,
		asEscapedCString({'z', 'z', '\x00', 'z', 'z', '\x00', 'z', 'z'}, 8)
	);
}

TEST_F(StringTests,
AsEscapedCStringCorrectlyEscapesCharAfterZeroByte) {
	// We cannot generate "a\\x00a" because that would mean a two-character
	// string composed of characters 'a' and '\x00a'.
	ASSERT_EQ(
		"a\\x00\\x61"s,
		asEscapedCString({'a', '\x00', '\x61'}, 8)
	);
}

//
// removeComments()
//

//void removeComments(std::string& str, char commentChar)

TEST_F(StringTests,
removeCommentsDoesNothingIfNoCommentsInString) {
	ASSERT_EQ(
		"hello world",
		removeComments("hello world", ';')
	);
}

TEST_F(StringTests,
removeCommentsRemovesCommentsFromString) {
	ASSERT_EQ(
		"hello world ",
		removeComments("hello world ; this should be removed", ';')
	);
}

TEST_F(StringTests,
removeCommentsRemovesDoesNotRemoveIfDifferentCommentCharProvided) {
	ASSERT_EQ(
		"hello world ; this should be removed",
		removeComments("hello world ; this should be removed", '/')
	);
}

} // namespace tests
} // namespace utils
} // namespace retdec
