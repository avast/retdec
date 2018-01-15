/**
* @file tests/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq_tests.cpp
* @brief Tests for the @c api_call_info_seq module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>

#include "retdec/llvmir2hll/pattern/pattern_finders/api_call/api_call_info_seq.h"

using namespace ::testing;

namespace retdec {
namespace llvmir2hll {
namespace tests {

/**
* @brief Tests for the @c api_call_info_seq module.
*/
class APICallInfoSeqTests: public ::testing::Test {};

//
// Copy constructor
//
TEST_F(APICallInfoSeqTests,
CopyConstructionWorkCorrectly) {
	APICallInfoSeq seq1;
	seq1.add(APICallInfo("func"));
	APICallInfoSeq seq2(seq1);
	EXPECT_EQ(seq1, seq2);
}

//
// operator=()
//

TEST_F(APICallInfoSeqTests,
AssignmentWorkCorrectly) {
	APICallInfoSeq seq1;
	seq1.add(APICallInfo("func"));
	APICallInfoSeq seq2;
	seq2 = seq1;
	EXPECT_EQ(seq1, seq2);
}

TEST_F(APICallInfoSeqTests,
AssignmentToSelfWorksCorrectly) {
	APICallInfoSeq seq;
	APICallInfo info("func");
	seq.add(info);
	seq = seq;
	EXPECT_EQ(info, seq.front());
}

//
// operator==()
// operator!=()
//

TEST_F(APICallInfoSeqTests,
TwoEmptySequencesAreEqual) {
	APICallInfoSeq seq1;
	APICallInfoSeq seq2;
	EXPECT_EQ(seq1, seq2);
}

TEST_F(APICallInfoSeqTests,
TwoNonEmptySequencesWithSameInformationAreEqual) {
	APICallInfoSeq seq1;
	seq1.add(APICallInfo("func"));
	APICallInfoSeq seq2;
	seq2.add(APICallInfo("func"));
	EXPECT_EQ(seq1, seq2);
}

TEST_F(APICallInfoSeqTests,
TwoNonEmptySequencesWithDifferentInformationAreNotEqual) {
	APICallInfoSeq seq1;
	seq1.add(APICallInfo("func"));
	APICallInfoSeq seq2;
	seq2.add(APICallInfo("func2"));
	EXPECT_NE(seq1, seq2);
}

//
// empty()
//

TEST_F(APICallInfoSeqTests,
SequenceUponCreationIsEmpty) {
	APICallInfoSeq seq;
	EXPECT_TRUE(seq.empty());
}

TEST_F(APICallInfoSeqTests,
WhenInfoIsAddedIntoEmptySequenceItIsNoLongerEmpty) {
	APICallInfoSeq seq;
	seq.add(APICallInfo("func"));
	EXPECT_FALSE(seq.empty());
}

//
// add()
//
TEST_F(APICallInfoSeqTests,
AddingThroughChainingAddCallsWorksCorrectly) {
	APICallInfoSeq seq;
	APICallInfo info1("func1");
	seq.add(info1);
	APICallInfo info2("func2");
	seq.add(info2);
	EXPECT_EQ(info1, seq.front());
	EXPECT_EQ(info2, seq.back());
}

//
// size()
//

TEST_F(APICallInfoSeqTests,
SizeOnEmptySequenceReturnsZero) {
	APICallInfoSeq seq;
	EXPECT_EQ(0, seq.size());
}

TEST_F(APICallInfoSeqTests,
SizeOnSequenceHavingTwoInfosReturnsTwo) {
	APICallInfoSeq seq;
	seq.add(APICallInfo("func1"))
		.add(APICallInfo("func2"));
	EXPECT_EQ(2, seq.size());
}

//
// front()
//

TEST_F(APICallInfoSeqTests,
FrontInNonEmptySequenceReturnsFirstInformation) {
	APICallInfoSeq seq;
	APICallInfo info1("func1");
	seq.add(info1);
	APICallInfo info2("func2");
	seq.add(info2);
	EXPECT_EQ(info1, seq.front());
}

//
// back()
//

TEST_F(APICallInfoSeqTests,
BackInNonEmptySequenceReturnsFirstInformation) {
	APICallInfoSeq seq;
	APICallInfo info1("func1");
	seq.add(info1);
	APICallInfo info2("func2");
	seq.add(info2);
	EXPECT_EQ(info2, seq.back());
}

//
// begin()
// end()
//

TEST_F(APICallInfoSeqTests,
IteratingOverInformationWorksCorrectly) {
	APICallInfoSeq seq;
	APICallInfo info1("func1");
	seq.add(info1);
	APICallInfo info2("func2");
	seq.add(info2);
	APICallInfo info3("func3");
	seq.add(info3);
	auto i = seq.begin();
	ASSERT_TRUE(i != seq.end());
	EXPECT_EQ(info1, *i);
	++i;
	ASSERT_TRUE(i != seq.end());
	EXPECT_EQ(info2, *i);
	++i;
	ASSERT_TRUE(i != seq.end());
	EXPECT_EQ(info3, *i);
	++i;
	ASSERT_TRUE(i == seq.end());
}

} // namespace tests
} // namespace llvmir2hll
} // namespace retdec
