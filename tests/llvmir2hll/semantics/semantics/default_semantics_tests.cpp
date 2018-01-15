/**
* @file tests/llvmir2hll/semantics/semantics/default_semantics_tests.cpp
* @brief Tests for the @c default_semantics module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/semantics/semantics/default_semantics.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c default_semantics module.
*/
class DefaultSemanticsTests: public Test {
protected:
	ShPtr<Semantics> semantics;

protected:
	virtual void SetUp() override {
		semantics = DefaultSemantics::create();
	}
};

TEST_F(DefaultSemanticsTests,
SemanticsHasNonEmptyID) {
	EXPECT_TRUE(!semantics->getId().empty()) <<
		"the semantics should have a non-empty ID";
}

TEST_F(DefaultSemanticsTests,
GetMainFuncNameReturnsNothing) {
	EXPECT_FALSE(semantics->getMainFuncName());
}

TEST_F(DefaultSemanticsTests,
GetCHeaderFileForFuncAlwaysReturnsNothing) {
	EXPECT_FALSE(semantics->getCHeaderFileForFunc("printf"));
	EXPECT_FALSE(semantics->getCHeaderFileForFunc("abs"));
	EXPECT_FALSE(semantics->getCHeaderFileForFunc("exit"));
}

TEST_F(DefaultSemanticsTests,
FuncNeverReturnsAlwaysReturnsNothing) {
	EXPECT_FALSE(semantics->funcNeverReturns("printf"));
	EXPECT_FALSE(semantics->funcNeverReturns("exit"));
	EXPECT_FALSE(semantics->funcNeverReturns("abort"));
}

TEST_F(DefaultSemanticsTests,
GetNameOfVarStoringResultAlwaysReturnsNothing) {
	EXPECT_FALSE(semantics->getNameOfVarStoringResult("getchar"));
	EXPECT_FALSE(semantics->getNameOfVarStoringResult("fopen"));
	EXPECT_FALSE(semantics->getNameOfVarStoringResult("socket"));
}

TEST_F(DefaultSemanticsTests,
GetNameOfParamAlwaysReturnsNothing) {
	EXPECT_FALSE(semantics->getNameOfParam("getchar", 1));
	EXPECT_FALSE(semantics->getNameOfParam("fopen", 2));
	EXPECT_FALSE(semantics->getNameOfParam("socket", 3));
}

TEST_F(DefaultSemanticsTests,
GetSymbolicNamesForParamAlwaysReturnsNothing) {
	EXPECT_FALSE(semantics->getSymbolicNamesForParam("flock", 2));
	EXPECT_FALSE(semantics->getSymbolicNamesForParam("socket", 2));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
