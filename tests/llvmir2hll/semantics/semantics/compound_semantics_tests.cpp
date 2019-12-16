/**
* @file tests/llvmir2hll/semantics/semantics/compound_semantics_tests.cpp
* @brief Tests for the @c compound_semantics module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/semantics/semantics/compound_semantics.h"
#include "llvmir2hll/semantics/semantics_mock.h"

using namespace ::testing;
using namespace std::string_literals;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c compound_semantics module.
*/
class CompoundSemanticsTests: public Test {
protected:
	ShPtr<CompoundSemantics> compoundSemantics;

protected:
	virtual void SetUp() override {
		compoundSemantics = CompoundSemantics::create();
	}
};

TEST_F(CompoundSemanticsTests,
SemanticsHasNonEmptyID) {
	EXPECT_TRUE(!compoundSemantics->getId().empty()) <<
		"the semantics should have a non-empty ID";
}

//
// getMainFuncName()
//

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->getMainFuncName());
}

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	ON_CALL(*semanticsMock, getMainFuncName())
		.WillByDefault(Return("main"s));
	compoundSemantics->appendSemantics(semantics);

	std::optional<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getMainFuncName())
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getMainFuncName())
		.WillByDefault(Return("main"s));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getMainFuncName())
		.WillByDefault(Return("main"s));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getMainFuncName())
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.value());
}

//
// getCHeaderFileForFunc()
//

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->getCHeaderFileForFunc("main"));
}

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	ON_CALL(*semanticsMock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return("stdio.h"s));
	compoundSemantics->appendSemantics(semantics);

	std::optional<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return("stdio.h"s));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return("stdio.h"s));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.value());
}

//
// funcNeverReturns()
//

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->funcNeverReturns("exit"));
}

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	ON_CALL(*semanticsMock, funcNeverReturns("exit"))
		.WillByDefault(Return(true));
	compoundSemantics->appendSemantics(semantics);

	std::optional<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.value());
}

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(true));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.value());
}

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(true));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.value());
}

//
// getNameOfVarStoringResult()
//

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->getNameOfVarStoringResult("main"));
}

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	ON_CALL(*semanticsMock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return("c"s));
	compoundSemantics->appendSemantics(semantics);

	std::optional<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return("c"s));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return("c"s));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.value());
}

//
// getNameOfParam()
//

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->getNameOfParam("fopen", 1));
}

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	ON_CALL(*semanticsMock, getNameOfParam("fopen", 1))
		.WillByDefault(Return("file_path"s));
	compoundSemantics->appendSemantics(semantics);

	std::optional<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return("file_path"s));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.value());
}

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return("file_path"s));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.value());
}

//
// getSymbolicNamesForParam()
//

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsNothingWhenThereIsNoSemantics) {
	EXPECT_FALSE(compoundSemantics->getSymbolicNamesForParam("flock", 2));
}

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsAnswerIfThereIsSingleSemanticsWhichKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	ON_CALL(*semanticsMock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(refMap));
	compoundSemantics->appendSemantics(semantics);

	std::optional<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.value());
}

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	ON_CALL(*semantics2Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(refMap));
	compoundSemantics->appendSemantics(semantics2);

	std::optional<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.value());
}

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	ON_CALL(*semantics1Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(refMap));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(std::nullopt));
	compoundSemantics->prependSemantics(semantics2);

	std::optional<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.value());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
