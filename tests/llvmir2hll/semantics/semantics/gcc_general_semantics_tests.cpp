/**
* @file tests/llvmir2hll/semantics/semantics/gcc_general_semantics_tests.cpp
* @brief Tests for the @c gcc_general_semantics module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/semantics/semantics/gcc_general_semantics.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c gcc_general_semantics module.
*/
class GCCGeneralSemanticsTests: public Test {
protected:
	ShPtr<Semantics> semantics;

protected:
	virtual void SetUp() override {
		semantics = GCCGeneralSemantics::create();
	}
};

TEST_F(GCCGeneralSemanticsTests,
SemanticsHasNonEmptyID) {
	EXPECT_TRUE(!semantics->getId().empty()) <<
		"the semantics should have a non-empty ID";
}

//
// getCHeaderFileForFunc()
//

TEST_F(GCCGeneralSemanticsTests,
GetCHeaderFileForKnownFunctionsReturnsCorrectAnswer) {
	// socket
	std::optional<std::string> headerForSocket(semantics->getCHeaderFileForFunc("socket"));
	ASSERT_TRUE(headerForSocket) << "no header file for `socket`";
	EXPECT_EQ("sys/socket.h", headerForSocket.value());
}

TEST_F(GCCGeneralSemanticsTests,
GetCHeaderFileForUnknownFunctionsReturnsNoAnswer) {
	// foo
	std::optional<std::string> headerForFoo(semantics->getCHeaderFileForFunc("foo"));
	EXPECT_FALSE(headerForFoo);
}

//
// getNameOfVarStoringResult()
//

TEST_F(GCCGeneralSemanticsTests,
GetNameOfVarStoringResultForKnownFunctionsReturnsCorrectAnswer) {
	// socket
	std::optional<std::string> socketVarName(semantics->getNameOfVarStoringResult("socket"));
	ASSERT_TRUE(socketVarName) << "no name of the variable storing the result of `socket`";
	EXPECT_EQ("sock_fd", socketVarName.value());
}

TEST_F(GCCGeneralSemanticsTests,
GetNameOfVarStoringResultForUnknownFunctionsReturnsNoAnswer) {
	// foo
	std::optional<std::string> fooVarName(semantics->getNameOfVarStoringResult("foo"));
	EXPECT_FALSE(fooVarName);
}

//
// getNameOfParam()
//

TEST_F(GCCGeneralSemanticsTests,
GetNameOfParamForKnownFunctionsReturnsCorrectAnswer) {
	// flock (first parameter)
	std::optional<std::string> flockParam1Name(semantics->getNameOfParam("flock", 1));
	ASSERT_TRUE(flockParam1Name) << "no name of the first parameter of `flock`";
	EXPECT_EQ("fd", flockParam1Name.value());

	// flock (second parameter)
	std::optional<std::string> flockParam2Name(semantics->getNameOfParam("flock", 2));
	ASSERT_TRUE(flockParam2Name) << "no name of the second parameter of `flock`";
	EXPECT_EQ("operation", flockParam2Name.value());
}

TEST_F(GCCGeneralSemanticsTests,
GetNameOfParamForUnknownFunctionsReturnsNoAnswer) {
	// foo
	std::optional<std::string> fooParam1Name(semantics->getNameOfParam("foo", 1));
	EXPECT_FALSE(fooParam1Name) << "there should be no information for `foo`";
}

//
// getSymbolicNamesForParam()
//

TEST_F(GCCGeneralSemanticsTests,
GetSymbolicNamesForParamForKnownFunctionsReturnsCorrectAnswer) {
	// flock
	std::optional<IntStringMap> flockSymbolicNames(semantics->getSymbolicNamesForParam("flock", 2));
	ASSERT_TRUE(flockSymbolicNames) << "no information for `flock`";

	IntStringMap refMap;
	refMap[1] = "LOCK_SH";
	refMap[2] = "LOCK_EX";
	refMap[4] = "LOCK_NB";
	refMap[8] = "LOCK_UN";
	EXPECT_EQ(refMap, flockSymbolicNames.value());
}

TEST_F(GCCGeneralSemanticsTests,
GetSymbolicNamesForParamForUnknownFunctionsReturnsNoAnswer) {
	// foo
	std::optional<IntStringMap> fooSymbolicNames(semantics->getSymbolicNamesForParam("foo", 1));
	EXPECT_FALSE(fooSymbolicNames);
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
