/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq_parser_tests.cpp
* @brief Tests for the @c api_call_info_seq_parser module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq_parser.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c api_call_info_seq_parser module.
*/
class APICallInfoSeqParserTests: public ::testing::Test {
protected:
	virtual void SetUp() override {
		parser = APICallInfoSeqParser::create();
		EXPECT_TRUE(parser);
	}

protected:
	ShPtr<APICallInfoSeqParser> parser;
};

TEST_F(APICallInfoSeqParserTests,
ParseOfEmptyStringReturnsEmptySequence) {
	Maybe<APICallInfoSeq> seq(parser->parse(""));
	ASSERT_TRUE(seq);
	EXPECT_TRUE(seq->empty());
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithNoBindsReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test()"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithBindToTheOnlyParameterReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test(X)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("X", info.getParamBind(1));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithBindToReturnValueAndOnlyParameterReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("X = test(Y)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	ASSERT_TRUE(info.hasBoundReturnValue());
	EXPECT_EQ("X", info.getReturnValueBind());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("Y", info.getParamBind(1));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithBindToReturnValueAndTwoParametersReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("X = test(Y, Z)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	ASSERT_TRUE(info.hasBoundReturnValue());
	EXPECT_EQ("X", info.getReturnValueBind());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("Y", info.getParamBind(1));
	ASSERT_TRUE(info.hasBoundParam(2));
	EXPECT_EQ("Z", info.getParamBind(2));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithBindToReturnValueAndThreeParametersReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("X = test(Y, Z, W)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	ASSERT_TRUE(info.hasBoundReturnValue());
	EXPECT_EQ("X", info.getReturnValueBind());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("Y", info.getParamBind(1));
	ASSERT_TRUE(info.hasBoundParam(2));
	EXPECT_EQ("Z", info.getParamBind(2));
	ASSERT_TRUE(info.hasBoundParam(3));
	EXPECT_EQ("W", info.getParamBind(3));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithBindAndUnderscoreReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test(X, _)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("X", info.getParamBind(1));
	EXPECT_FALSE(info.hasBoundParam(2));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithUnderscoreAndBindReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test(_, X)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	EXPECT_FALSE(info.hasBoundParam(1));
	ASSERT_TRUE(info.hasBoundParam(2));
	EXPECT_EQ("X", info.getParamBind(2));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithJustUnderscoresReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test(_, _, _)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("test", info.getFuncName());
	EXPECT_FALSE(info.hasBoundParam(1));
	EXPECT_FALSE(info.hasBoundParam(2));
	EXPECT_FALSE(info.hasBoundParam(3));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfTwoInfosWithNoBindsReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("test1()\ntest2()"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(2, seq->size());
	const APICallInfo &info1(seq->front());
	EXPECT_EQ("test1", info1.getFuncName());
	const APICallInfo &info2(seq->back());
	EXPECT_EQ("test2", info2.getFuncName());
}

TEST_F(APICallInfoSeqParserTests,
ParseOfThreeInfosWithManyBindsReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse(
		"X = test1()\n"
		"test2(X, _)\n"
		"test3(X)\n"
	));
	ASSERT_TRUE(seq);
	ASSERT_EQ(3, seq->size());
	auto i = seq->begin();
	const APICallInfo &info1(*i++);
	EXPECT_EQ("test1", info1.getFuncName());
	EXPECT_FALSE(info1.hasBoundParam(1));
	ASSERT_TRUE(info1.hasBoundReturnValue());
	EXPECT_EQ("X", info1.getReturnValueBind());
	const APICallInfo &info2(*i++);
	EXPECT_EQ("test2", info2.getFuncName());
	EXPECT_TRUE(info2.hasBoundParam(1));
	EXPECT_EQ("X", info2.getParamBind(1));
	EXPECT_FALSE(info2.hasBoundParam(2));
	const APICallInfo &info3(*i++);
	EXPECT_EQ("test3", info3.getFuncName());
	EXPECT_TRUE(info3.hasBoundParam(1));
	EXPECT_EQ("X", info3.getParamBind(1));
}

TEST_F(APICallInfoSeqParserTests,
ParseOfSingleInfoWithMulticharacterBindsReturnsCorrectResult) {
	Maybe<APICallInfoSeq> seq(parser->parse("012 = MyFunc99(Y2abc)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("MyFunc99", info.getFuncName());
	ASSERT_TRUE(info.hasBoundReturnValue());
	EXPECT_EQ("012", info.getReturnValueBind());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("Y2abc", info.getParamBind(1));
}

TEST_F(APICallInfoSeqParserTests,
WhitespaceDoesNotMatter) {
	Maybe<APICallInfoSeq> seq(parser->parse("\v\nX   =  \t test (\n\r\n)   "));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
}

TEST_F(APICallInfoSeqParserTests,
IdsCanHaveUnderscoresInTheirNames) {
	Maybe<APICallInfoSeq> seq(parser->parse("_te__st(_X, _, _Y)"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(1, seq->size());
	const APICallInfo &info(seq->front());
	EXPECT_EQ("_te__st", info.getFuncName());
	ASSERT_TRUE(info.hasBoundParam(1));
	EXPECT_EQ("_X", info.getParamBind(1));
	EXPECT_FALSE(info.hasBoundParam(2));
	ASSERT_TRUE(info.hasBoundParam(3));
	EXPECT_EQ("_Y", info.getParamBind(3));
}

TEST_F(APICallInfoSeqParserTests,
ThereDoesNotNeedToBeSpaceToSeparateTwoInfos) {
	Maybe<APICallInfoSeq> seq(parser->parse("test1()test2()"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(2, seq->size());
	const APICallInfo &info1(seq->front());
	EXPECT_EQ("test1", info1.getFuncName());
	const APICallInfo &info2(seq->back());
	EXPECT_EQ("test2", info2.getFuncName());
}

TEST_F(APICallInfoSeqParserTests,
SemicolonCanBeOptionallyUsedAsEndOfInfos) {
	Maybe<APICallInfoSeq> seq(parser->parse("test1();test2();"));
	ASSERT_TRUE(seq);
	ASSERT_EQ(2, seq->size());
	const APICallInfo &info1(seq->front());
	EXPECT_EQ("test1", info1.getFuncName());
	const APICallInfo &info2(seq->back());
	EXPECT_EQ("test2", info2.getFuncName());
}

TEST_F(APICallInfoSeqParserTests,
ParseOfInvalidRepresentationReturnsNothing) {
	EXPECT_FALSE(parser->parse("##"));
	EXPECT_FALSE(parser->parse(";"));
	EXPECT_FALSE(parser->parse(";;"));
	EXPECT_FALSE(parser->parse("test();;"));
	EXPECT_FALSE(parser->parse("()"));
	EXPECT_FALSE(parser->parse("test)"));
	EXPECT_FALSE(parser->parse("test("));
	EXPECT_FALSE(parser->parse("test"));
	EXPECT_FALSE(parser->parse("test(,"));
	EXPECT_FALSE(parser->parse("test(X,"));
	EXPECT_FALSE(parser->parse("test(()"));
	EXPECT_FALSE(parser->parse("test())"));
	EXPECT_FALSE(parser->parse("test(,)"));
	EXPECT_FALSE(parser->parse("test(X X)"));
	EXPECT_FALSE(parser->parse("test test()"));
	EXPECT_FALSE(parser->parse("= test()"));
	EXPECT_FALSE(parser->parse("X ="));
	EXPECT_FALSE(parser->parse("X = ()"));
	EXPECT_FALSE(parser->parse("X = test"));
	EXPECT_FALSE(parser->parse("X X = test()"));
	EXPECT_FALSE(parser->parse("X = = test()"));
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
