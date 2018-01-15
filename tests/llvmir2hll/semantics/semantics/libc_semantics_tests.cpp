/**
* @file tests/llvmir2hll/semantics/semantics/libc_semantics_tests.cpp
* @brief Tests for the @c libc_semantics module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/semantics/semantics/libc_semantics.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c libc_semantics module.
*/
class LibcSemanticsTests: public Test {
protected:
	ShPtr<Semantics> semantics;

protected:
	virtual void SetUp() override {
		semantics = LibcSemantics::create();
	}
};

//
// getId()
//

TEST_F(LibcSemanticsTests,
SemanticsHasNonEmptyID) {
	EXPECT_TRUE(!semantics->getId().empty()) <<
		"the semantics should have a non-empty ID";
}

//
// getMainFuncName()
//

TEST_F(LibcSemanticsTests,
GetMainFuncNameReturnsMain) {
	Maybe<std::string> mainFuncName(semantics->getMainFuncName());
	ASSERT_TRUE(mainFuncName);
	EXPECT_EQ("main", mainFuncName.get());
}

//
// getCHeaderFileForFunc()
//

TEST_F(LibcSemanticsTests,
GetCHeaderFileForKnownFunctionsReturnsCorrectAnswer) {
	// printf
	Maybe<std::string> headerForPrintf(semantics->getCHeaderFileForFunc("printf"));
	ASSERT_TRUE(headerForPrintf) << "no header file for `print`";
	EXPECT_EQ("stdio.h", headerForPrintf.get());

	// exit
	Maybe<std::string> headerForExit(semantics->getCHeaderFileForFunc("exit"));
	ASSERT_TRUE(headerForExit) << "no header file for `exit`";
	EXPECT_EQ("stdlib.h", headerForExit.get());

	// fabs
	Maybe<std::string> headerForFabs(semantics->getCHeaderFileForFunc("fabs"));
	ASSERT_TRUE(headerForFabs) << "no header file for `fabs`";
	EXPECT_EQ("math.h", headerForFabs.get());

	// signal
	Maybe<std::string> headerForSignal(semantics->getCHeaderFileForFunc("signal"));
	ASSERT_TRUE(headerForSignal) << "no header file for `signal`";
	EXPECT_EQ("signal.h", headerForSignal.get());
}

TEST_F(LibcSemanticsTests,
GetCHeaderFileForUnknownFunctionsReturnsNoAnswer) {
	// foo
	Maybe<std::string> headerForFoo(semantics->getCHeaderFileForFunc("foo"));
	EXPECT_FALSE(headerForFoo);
}

//
// funcNeverReturns()
//

TEST_F(LibcSemanticsTests,
FuncNeverReturnsForKnownFunctionsThatNeverReturnsReturnsTrue) {
	// exit
	Maybe<bool> exitNeverReturns(semantics->funcNeverReturns("exit"));
	ASSERT_TRUE(exitNeverReturns) << "no information for `exit`";
	EXPECT_TRUE(exitNeverReturns.get());

	// abort
	Maybe<bool> abortNeverReturns(semantics->funcNeverReturns("abort"));
	ASSERT_TRUE(abortNeverReturns) << "no information for `abort`";
	EXPECT_TRUE(abortNeverReturns.get());
}

TEST_F(LibcSemanticsTests,
FuncNeverReturnsForUnknownFunctionsReturnsNoAnswer) {
	// foo
	Maybe<bool> fooNeverReturns(semantics->funcNeverReturns("foo"));
	ASSERT_FALSE(fooNeverReturns) << "there should be no information for `foo`";
}

//
// getNameOfVarStoringResult()
//

TEST_F(LibcSemanticsTests,
GetNameOfVarStoringResultForKnownFunctionsReturnsCorrectAnswer) {
	// getchar
	Maybe<std::string> getcharVarName(semantics->getNameOfVarStoringResult("getchar"));
	ASSERT_TRUE(getcharVarName) << "no name of the variable storing the result of `getchar`";
	EXPECT_EQ("c", getcharVarName.get());

	// fgetc
	Maybe<std::string> fgetcVarName(semantics->getNameOfVarStoringResult("fgetc"));
	ASSERT_TRUE(fgetcVarName) << "no name of the variable storing the result of `fgetc`";
	EXPECT_EQ("c", fgetcVarName.get());
}

TEST_F(LibcSemanticsTests,
GetNameOfVarStoringResultForUnknownFunctionsReturnsNoAnswer) {
	// foo
	Maybe<std::string> fooVarName(semantics->getNameOfVarStoringResult("foo"));
	EXPECT_FALSE(fooVarName);
}

//
// getNameOfParam()
//

TEST_F(LibcSemanticsTests,
GetNameOfParamForKnownFunctionsReturnsCorrectAnswer) {
	// fopen (first parameter)
	Maybe<std::string> fopenParam1Name(semantics->getNameOfParam("fopen", 1));
	ASSERT_TRUE(fopenParam1Name) << "no name of the first parameter of `fopen`";
	EXPECT_EQ("file_path", fopenParam1Name.get());

	// fopen (second parameter)
	Maybe<std::string> fopenParam2Name(semantics->getNameOfParam("fopen", 2));
	ASSERT_TRUE(fopenParam2Name) << "no name of the second parameter of `fopen`";
	EXPECT_EQ("mode", fopenParam2Name.get());
}

TEST_F(LibcSemanticsTests,
GetNameOfParamForUnknownFunctionsReturnsNoAnswer) {
	// foo
	Maybe<std::string> fooParam1Name(semantics->getNameOfParam("foo", 1));
	EXPECT_FALSE(fooParam1Name) << "there should be no information for `foo`";
}

//
// getSymbolicNamesForParam()
//

TEST_F(LibcSemanticsTests,
GetSymbolicNamesForParamForKnownFunctionsReturnsCorrectAnswer) {
	// fseek
	Maybe<IntStringMap> fseekSymbolicNames(semantics->getSymbolicNamesForParam("fseek", 3));
	ASSERT_TRUE(fseekSymbolicNames) << "no information for `fseek`";

	IntStringMap refMap;
	refMap[0] = "SEEK_SET";
	refMap[1] = "SEEK_CUR";
	refMap[2] = "SEEK_END";

	EXPECT_EQ(refMap, fseekSymbolicNames.get());
}

TEST_F(LibcSemanticsTests,
GetSymbolicNamesForParamForUnknownFunctionsReturnsNoAnswer) {
	// foo
	Maybe<IntStringMap> fooSymbolicNames(semantics->getSymbolicNamesForParam("foo", 1));
	EXPECT_FALSE(fooSymbolicNames);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
