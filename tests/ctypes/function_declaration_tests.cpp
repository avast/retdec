/**
* @file tests/ctypes/function_declaration_tests.cpp
* @brief Tests for the @c function_declaration module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include <gtest/gtest.h>

#include "retdec/ctypes/function_declaration.h"

using namespace ::testing;

namespace retdec {
namespace ctypes {
namespace tests {

class FunctionDeclarationTests : public Test {};

TEST_F(FunctionDeclarationTests,
GetStringDeclarationReturnsCorrectDeclaration)
{
	EXPECT_EQ(
		"int f(int i);",
		std::string(FunctionDeclaration("int f(int i);"))
	);
}

TEST_F(FunctionDeclarationTests,
DeafultConstructorCreatesEmptyFunctionDeclaration)
{
	FunctionDeclaration function_declaration;

	EXPECT_EQ("", std::string(function_declaration));
}

} // namespace tests
} // namespace ctypes
} // namespace retdec
