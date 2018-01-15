/**
* @file tests/bin2llvmir/analyses/tests/var_depend_analysis_tests.cpp
* @brief Tests for the @c VarDependAnalysis analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <gtest/gtest.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>

#include "retdec/bin2llvmir/analyses/var_depend_analysis.h"

using namespace ::testing;
using namespace llvm;

namespace retdec {
namespace bin2llvmir {
namespace tests {

/**
* @brief Tests for the @c VarDependAnalysis analysis.
*/
class VarDependAnalysisTests: public Test {
protected:
	void compareResults(const VarDependAnalysis::PHINodeVec &out, const
		VarDependAnalysis::PHINodeVec &ref);

protected:
	/// LLVM context used in tests.
	LLVMContext context;

	/// Variable analysis.
	VarDependAnalysis analysis;
};

/**
* @brief Compares the result of analysis.
*
* @param[in] out Output vector of PHI nodes from analysis.
* @param[in] ref Reference vector of PHI nodes.
*/
void VarDependAnalysisTests::compareResults(const VarDependAnalysis::PHINodeVec
		&out, const VarDependAnalysis::PHINodeVec &ref) {
	ASSERT_TRUE(out.size() == ref.size()) <<
			" Expected same count of PHI nodes. \n"
			<< "Output vector has size : " << out.size() << "\n"
			<< "Reference vector has size: " << ref.size();

	VarDependAnalysis::PHINodeVec::const_iterator itOut(out.begin());

	for (VarDependAnalysis::PHINodeVec::const_iterator iRef = ref.begin(),
			eRef = ref.end(); iRef != eRef; ++iRef) {
		EXPECT_EQ((*itOut)->getName(), (*iRef)->getName());
		++itOut;
	}
}

TEST_F(VarDependAnalysisTests,
AnalysisHasNonEmptyID) {
	EXPECT_TRUE(!analysis.getId().empty()) <<
		"the analysis should have a non-empty ID";
}

TEST_F(VarDependAnalysisTests,
VarDependencyWithoutCyclesTest) {
	// Testing result of variable dependency analysis. No cycles in input.
	//
	// B = phi i32 []
	// A = phi i32 [ %B, %first ]
	// C = phi i32 [ %A, %first ]

	// Expected result of analysis:
	// C = phi i32 [ %A, %first ]
	// A = phi i32 [ %B, %first ]
	//

	// Creating input of test.
	BasicBlock* fstBB(BasicBlock::Create(context, "first"));
	PHINode *phiNodeA(PHINode::Create(Type::getInt32Ty(context),
		1, "A"));
	PHINode *phiNodeB(PHINode::Create(Type::getInt32Ty(context),
		1, "B"));
	PHINode *phiNodeC(PHINode::Create(Type::getInt32Ty(context),
		1, "C"));
	phiNodeA->addIncoming(phiNodeB->getValueName()->second, fstBB);
	phiNodeC->addIncoming(phiNodeA->getValueName()->second, fstBB);

	// Initializing variable dependency analysis.
	analysis.addEdge("B", "A", *fstBB, phiNodeA);
	analysis.addEdge("A", "C", *fstBB, phiNodeC);

	// Analyzing
	const VarDependAnalysis::PHINodeVec &out(analysis.
		detectNonCycleVarDependency());

	// Creating reference output.
	VarDependAnalysis::PHINodeVec ref;
	ref.push_back(phiNodeC);
	ref.push_back(phiNodeA);

	compareResults(out, ref);

	// Clearing after test.
	analysis.clear();
}

TEST_F(VarDependAnalysisTests,
CycleDependencyTwoCyclesTest) {
	// Testing result of variable dependency analysis. Two cycles in input.
	//
	// B = phi i32 [ %A, %first ]
	// A = phi i32 [ %B, %first ]
	// C = phi i32 [ %D, %second ]
	// D = phi i32 [ %C, %second ]

	// Expected result of analysis:
	// B = phi i32 [ %A, %first ]
	// C = phi i32 [ %D, %second ]
	//

	// Creating input of test.
	BasicBlock *fstBBB(BasicBlock::Create(context, "first"));
	BasicBlock *sndBB(BasicBlock::Create(context, "second"));
	PHINode *phiNodeA(PHINode::Create(Type::getInt32Ty(context), 1,
		"A"));
	PHINode *phiNodeB(PHINode::Create(Type::getInt32Ty(context),
		1, "B"));
	PHINode *phiNodeC(PHINode::Create(Type::getInt32Ty(context),
		1, "C"));
	PHINode *phiNodeD(PHINode::Create(Type::getInt32Ty(context),
		1, "D"));
	phiNodeA->addIncoming(phiNodeB->getValueName()->second, fstBBB);
	phiNodeB->addIncoming(phiNodeA->getValueName()->second, fstBBB);
	phiNodeC->addIncoming(phiNodeD->getValueName()->second, sndBB);
	phiNodeD->addIncoming(phiNodeC->getValueName()->second, sndBB);

	// Initializing variable dependency analysis.
	analysis.addEdge("A", "B", *fstBBB, phiNodeB);
	analysis.addEdge("B", "A", *fstBBB, phiNodeA);
	analysis.addEdge("D", "C", *sndBB, phiNodeC);
	analysis.addEdge("C", "D", *sndBB, phiNodeD);

	// Analyzing
	const VarDependAnalysis::StringBBVecOfPHINodesMap &out(analysis.
		detectCycleVarDependency());

	// Creating reference output for first cycle.
	VarDependAnalysis::PHINodeVec fstRef;
	fstRef.push_back(phiNodeB);

	// Parsing output for first cycle.
	VarDependAnalysis::StringBBVecOfPHINodesMap::const_iterator it(out.begin());
	VarDependAnalysis::PHINodeVec fstResult(it->second.phiNodeVec);
	ASSERT_EQ(fstBBB->getName(), it->first) <<
		" Names of basic blocks have to be same";

	{
		SCOPED_TRACE("compareResults - comparing result of the first result.");
		compareResults(fstResult, fstRef);
	}

	// Creating reference output for second cycle.
	VarDependAnalysis::PHINodeVec sndRef;
	sndRef.push_back(phiNodeC);

	// Parsing output for second cycle.
	it++;
	VarDependAnalysis::PHINodeVec sndResult(it->second.phiNodeVec);
	ASSERT_EQ(sndBB->getName(), it->first) <<
		" Names of basic blocks have to be same";

	{
		SCOPED_TRACE("compareResults - comparing result of the second cycle.");
		compareResults(sndResult, sndRef);
	}

	// Clearing after test.
	analysis.clear();
}

} // namespace tests
} // namespace bin2llvmir
} // namespace retdec
