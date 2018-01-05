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
		.WillByDefault(Return(Just("main"s)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getMainFuncName())
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getMainFuncName())
		.WillByDefault(Return(Just("main"s)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetMainFuncNameReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getMainFuncName())
		.WillByDefault(Return(Just("main"s)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getMainFuncName())
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getMainFuncName());
	ASSERT_TRUE(answer);
	EXPECT_EQ("main", answer.get());
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
		.WillByDefault(Return(Just("stdio.h"s)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just("stdio.h"s)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetCHeaderFileForFuncReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Just("stdio.h"s)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getCHeaderFileForFunc("printf"))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("stdio.h", answer.get());
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
		.WillByDefault(Return(Just(true)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.get());
}

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(Nothing<bool>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(Just(true)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.get());
}

TEST_F(CompoundSemanticsTests,
FuncNeverReturnsReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(Just(true)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, funcNeverReturns("exit"))
		.WillByDefault(Return(Nothing<bool>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<bool> answer(compoundSemantics->funcNeverReturns("exit"));
	ASSERT_TRUE(answer);
	EXPECT_TRUE(answer.get());
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
		.WillByDefault(Return(Just("c"s)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(Just("c"s)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetNameOfVarStoringResultReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(Just("c"s)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfVarStoringResult("getchar"))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(answer);
	EXPECT_EQ("c", answer.get());
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
		.WillByDefault(Return(Just("file_path"s)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Just("file_path"s)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.get());
}

TEST_F(CompoundSemanticsTests,
GetNameOfParamReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Just("file_path"s)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getNameOfParam("fopen", 1))
		.WillByDefault(Return(Nothing<std::string>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<std::string> answer(compoundSemantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(answer);
	EXPECT_EQ("file_path", answer.get());
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
		.WillByDefault(Return(Just(refMap)));
	compoundSemantics->appendSemantics(semantics);

	Maybe<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.get());
}

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsAnswerIfSecondSemanticsAddedByAppendKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	ON_CALL(*semantics1Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(Nothing<IntStringMap>()));
	compoundSemantics->appendSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	ON_CALL(*semantics2Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(Just(refMap)));
	compoundSemantics->appendSemantics(semantics2);

	Maybe<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.get());
}

TEST_F(CompoundSemanticsTests,
GetSymbolicNamesForParamReturnsAnswerIfSecondSemanticsAddedByPrependKnowsTheAnswer) {
	INSTANTIATE_SEMANTICS_MOCK(semantics1);
	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	ON_CALL(*semantics1Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(Just(refMap)));
	compoundSemantics->prependSemantics(semantics1);

	INSTANTIATE_SEMANTICS_MOCK(semantics2);
	ON_CALL(*semantics2Mock, getSymbolicNamesForParam("flock", 2))
		.WillByDefault(Return(Nothing<IntStringMap>()));
	compoundSemantics->prependSemantics(semantics2);

	Maybe<IntStringMap> answer(compoundSemantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(answer);
	EXPECT_EQ(refMap, answer.get());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
