/**
 * @file tests/config/language_tests.cpp
 * @brief Tests for the @c address module.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <gtest/gtest.h>

#include "retdec/config/language.h"

using namespace ::testing;

namespace retdec {
namespace config {
namespace tests {

//
//=============================================================================
//  LanguageTests
//=============================================================================
//

class LanguageTests : public Test
{

};

//
//=============================================================================
//  LanguageContainerTests
//=============================================================================
//

class LanguageContainerTests : public Test
{
	public:
		LanguageContainerTests() :
				lang1("lang1"),
				lang2("lang2"),
				lang3("lang3")
		{
			langs.insert(lang1);

			langs.insert(lang2);

			lang3.setIsBytecode(true);
			langs.insert(lang3);
		}

	protected:
		Language lang1;
		Language lang2;
		Language lang3;
		LanguageContainer langs;
};

TEST_F(LanguageContainerTests, TestGetFirstBytecodeFound)
{
	auto* l = langs.getFirstBytecode();
	ASSERT_TRUE(l != nullptr);
	EXPECT_EQ( lang3.getName(), l->getName() );
}

TEST_F(LanguageContainerTests, TestGetFirstBytecodeNotFound)
{
	LanguageContainer lc;
	lc.insert(lang1);
	lc.insert(lang2);

	auto* n = lc.getFirstBytecode();
	ASSERT_TRUE(n == nullptr);
}

TEST_F(LanguageContainerTests, TestHasLanguageFindsLanguageIfItExists)
{
	LanguageContainer lc;
	lc.insert(Language("some language"));
	lc.insert(Language("CIL/.NET (bytecode)"));

	EXPECT_TRUE(lc.hasLanguage(".NET"));
}

TEST_F(LanguageContainerTests, TestHasLanguageFindsLanguageIfItExistsCaseInsensitive)
{
	LanguageContainer lc;
	lc.insert(Language("some language"));
	lc.insert(Language("CIL/.NET (bytecode)"));

	EXPECT_TRUE(lc.hasLanguage("cil/.net"));
}

TEST_F(LanguageContainerTests, TestHasLanguageDoesNotFindLanguageIfItDoesNotExist)
{
	LanguageContainer lc;
	lc.insert(Language("some language"));
	lc.insert(Language("CIL/.NET (bytecode)"));

	EXPECT_FALSE(lc.hasLanguage("C++"));
}

} // namespace tests
} // namespace config
} // namespace retdec
