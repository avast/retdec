/**
* @file src/bin2llvmir/optimizations/phi2seq/phi2seq.cpp
* @brief Implementation of PHI2seq.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <llvm/ADT/StringMap.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Scalar.h>

#include "retdec/bin2llvmir/optimizations/phi2seq/phi2seq.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/// Suffix of name for predecessor temp basic block.
const std::string SUFFIX_OF_PRE_BLOCK_NAME = ".phi2seq.pre";

/// Suffix of name for temp PHI node.
const std::string SUFFIX_OF_VAR_TMP_NAME = ".phi2seq.tmp";

} // anonymous namespace

const char* PHI2Seq::NAME = "phi2seq";

// It is the address of the variable that matters, not the value, so we can
// initialize the ID to anything.
char PHI2Seq::ID = 0;

RegisterPass<PHI2Seq> PHI2SeqRegistered(PHI2Seq::getName(),
	"Phi2Seq optimization", false, false);

/**
* @brief Constructs a new optimizer.
*/
PHI2Seq::PHI2Seq(): FunctionPass(ID) {}

/**
* @brief Destructs the optimizer.
*/
PHI2Seq::~PHI2Seq() {}

void PHI2Seq::getAnalysisUsage(AnalysisUsage& au) const {
	au.addRequiredID(InstructionNamerID);
}

bool PHI2Seq::runOnFunction(Function &func) {
	// Iterate through basic blocks.
	for (BasicBlock &bb : func) {
		orderDependentPHINodesAndSolveCycles(bb);
	}

	return true;
}

/**
* @brief Orders PHI nodes in the given basic block according to their
*        dependencies and solves cycles.
*
* @param[in, out] bb Basic block to order.
*/
void PHI2Seq::orderDependentPHINodesAndSolveCycles(BasicBlock &bb) {
	initVarDependAnalysis(bb);

	// Solving cycle variable dependency.
	solveCycleVarDependency(bb, varDependAnalysis.detectCycleVarDependency());

	// Solving non-cycle variable dependency.
	orderDependentPHINodes(bb, varDependAnalysis.detectNonCycleVarDependency());
}

/**
* @brief Initializes variable dependency analysis.
*
* @param[in] bb Basic block to analyze.
*/
void PHI2Seq::initVarDependAnalysis(BasicBlock &bb) {
	// Each basic block needs to have its own analysis.
	varDependAnalysis.clear();

	iteratePHINodesAndInitVarDependAnalysis(bb);
}

/**
* @brief Iterates through @a bb and initializes variable dependency analysis.
*
* @param[in] bb Basic block to analyze.
*/
void PHI2Seq::iteratePHINodesAndInitVarDependAnalysis(BasicBlock &bb) {
	auto it = bb.begin();
	while (PHINode *phiNode = dyn_cast<llvm::PHINode>(it)) {
		iterateIncValuesAndInitVarDependAnalysis(*phiNode);
		++it;
	}
}

/**
* @brief Iterates through @a phiNode and adds incoming values to variable
*        dependency analysis.
*
* @param[in] phiNode PHI node to iterate.
*/
void PHI2Seq::iterateIncValuesAndInitVarDependAnalysis(PHINode &phiNode) {
	for (unsigned j = 0, k = phiNode.getNumIncomingValues(); j < k; ++j) {
		Value *incValue(phiNode.getIncomingValue(j));
		BasicBlock *incBB(phiNode.getIncomingBlock(j));
		std::string lVarName(phiNode.getName());
		std::string incVarName(incValue->getName());
		if (!incVarName.empty() && lVarName != incVarName) {
			// We support only variables with name.
			//
			// If incoming variable has same name with variable that is
			// assigned we don't need to do something with this, because
			// parallel processing is same like sequential.

			// Creating edge in variable dependency analysis has some
			// conditions.
			// For example:
			//    %A = phi i32 [ %B, %bb1 ]
			//
			// We must create edge from B -> A.
			varDependAnalysis.addEdge(incVarName, lVarName, *incBB, &phiNode);
		}
	}
}

/**
* @brief Solves cycle variable dependency in @a bb.
*
* @param[in, out] bb Basic block to solve.
* @param[in] cyclesDetectResult Result of variable dependency analysis.
*/
void PHI2Seq::solveCycleVarDependency(BasicBlock &bb, const VarDependAnalysis::
		StringBBVecOfPHINodesMap &cyclesDetectResult) {
	// Iterates through results of cycle variable dependency analysis.
	for (auto &item : cyclesDetectResult) {
		// Create pre basic block.
		BasicBlock &preTmpBB(createPreBBAndSolveConnection(item.second, bb));

		// Updates predecessors and values in cycled PHI nodes.
		updateBBWithCycle(bb, *item.second.bb, preTmpBB);
	}
}

/**
* @brief Creates predecessor temp basic block for basic block with cycle.
*        Also solve connection with other basic blocks.
*
* @param[in] bbWithPHINodesVec Basic block with PHI nodes vector. For these PHI
*            nodes are created temp PHI nodes.
* @param[in] currBB Basic block that contains cycle of PHI nodes.
*/
BasicBlock &PHI2Seq::createPreBBAndSolveConnection(const VarDependAnalysis::
		BBVecOfPHINodes &bbWithPHINodesVec, BasicBlock &currBB) {
	// Get name and create temp basic block.
	std::string preTmpBBName(currBB.getName().str() + SUFFIX_OF_PRE_BLOCK_NAME);
	BasicBlock *preTmpBB(BasicBlock::Create(currBB.getContext(), preTmpBBName,
		currBB.getParent(), &currBB));
	IRBuilder<> builder(preTmpBB);

	// We create the following connection:
	// Predecessor of BlockWithCycle -> temp block for blockWithCycle ->
	// BlockWithCycle.
	updateBBTermInstr(*bbWithPHINodesVec.bb, currBB, *preTmpBB);

	// Create new temp PHI nodes in temp basic block.
	createTmpPHINodes(builder, bbWithPHINodesVec);

	// Create branch to basic block with cycle.
	builder.CreateBr(&currBB);

	return *preTmpBB;
}

/**
* @brief Updates successor in termination instruction in @a bbToUpdate from @a
*        oldSucc to @a newSucc.
*
* @param[in, out] bbToUpdate Basic block to update.
* @param[in] oldSucc Old successor.
* @param[in] newSucc New successor.
*/
void PHI2Seq::updateBBTermInstr(BasicBlock &bbToUpdate, BasicBlock &oldSucc,
		BasicBlock &newSucc) {
	TerminatorInst *termInstr(bbToUpdate.getTerminator());
	for (unsigned j = 0, k = termInstr->getNumSuccessors(); j < k; ++j) {
		if (termInstr->getSuccessor(j)->getName() == oldSucc.getName()) {
			termInstr->setSuccessor(j, &newSucc);
		}
	}
}

/**
* @brief Creates temp PHI nodes in new temp basic block.
*
* Also save new and old value that have to be replaced in basic block with cycle.
* This things are saved in @c vecOfPHINodesToSubs.
*
* @param[in] builder Builder for new temp basic block.
* @param[in] bbWithPHINodesVec Basic block with PHI nodes vector. For these PHI
*            nodes are created temp PHI nodes.
*/
void PHI2Seq::createTmpPHINodes(IRBuilder<> &builder,
		const VarDependAnalysis::BBVecOfPHINodes &bbWithPHINodesVec) {
	// Iterates through PHI nodes to optimize and create temp PHI nodes.
	for (PHINode *phiNode : bbWithPHINodesVec.phiNodeVec) {
		// Get incoming value and create name for new temp PHI node.
		Value *incValue(phiNode->getIncomingValueForBlock(bbWithPHINodesVec.bb));
		std::string lvarName(incValue->getName().str() + SUFFIX_OF_VAR_TMP_NAME);

		// Create new temp PHI node.
		PHINode *createdPHINode(builder.CreatePHI(phiNode->getType(), 1,
			lvarName));
		createdPHINode->addIncoming(incValue, bbWithPHINodesVec.bb);

		// Add information for later update PHI nodes in basic block with cycle.
		phiNodeToSubsVec.push_back(PHINodeToSubs(phiNode, incValue,
			createdPHINode->getValueName()->getValue()));
	}
}

/**
* @brief Updates values and predecessors in PHI nodes in @a bb.
*
* Updates values. Example:
* @code
* %A = [ %B, %.bb ]
* to
* %A = [ %B.phi2seq.tmp, %.bb ]
* @endcode
*
* Updates predecessors in PHI nodes. Example:
* @code
* %A = [ %B.phi2seq.tmp, %.bb ]
* to
* %A = [ %B.phi2seq.tmp, %.bb.phi2seq.pre ]
* @endcode
*
* @param[in, out] bb Basic block with cycle.
* @param[in] oldBB Old predecessor block in PHI nodes.
* @param[in] newBB New predecessor block in PHI nodes.
*/
void PHI2Seq::updateBBWithCycle(BasicBlock &bbWithCycle, BasicBlock &oldBB,
		BasicBlock &newBB) {
	for (PHINodeToSubs &phiNodeToSubs : phiNodeToSubsVec) {
		PHINode *phiNodeToUpdate(phiNodeToSubs.phiNodeToSubs);

		// Update value in PHI node.
		replaceValueForPHINode(*phiNodeToUpdate, *phiNodeToSubs.oldValue,
			*phiNodeToSubs.newValue, oldBB);

		// Create in analysis new edge for updated PHI node.
		varDependAnalysis.addEdge(phiNodeToSubs.newValue->getName(),
			phiNodeToUpdate->getName(), newBB, phiNodeToUpdate);
	}

	// Update predecessors in PHI nodes. We updates only one predecessor basic
	// block in phi nodes, so need to run at the end.
	updatePredecessorsInPHINodes(bbWithCycle, oldBB, newBB);

	// Need to clear after updates.
	phiNodeToSubsVec.clear();
}

/**
* @brief Updates @a oldValue in @a phiNodeToUpdate with @a newValue.
*
* @param[in] phiNodeToUpdate For this PHI node is value updated.
* @param[in] oldValue Old value that will be updated.
* @param[in] newValue To this value will be updated old value.
* @param[in] pred We are replacing value for this predecessor.
*/
void PHI2Seq::replaceValueForPHINode(PHINode &phiNodeToUpdate, Value &oldValue,
		Value &newValue, BasicBlock &pred) {
	for (unsigned i = 0, e = phiNodeToUpdate.getNumOperands(); i < e; ++i) {
		if (phiNodeToUpdate.getOperand(i) == &oldValue &&
				phiNodeToUpdate.getIncomingBlock(i) == &pred) {
			// Example:
			//   oldValue = %var1, newValue = %var.phi2seq.tmp,
			//   pred = %bb1.
			//   phiNodeToUpdate = phi i8* [ %var1, %bb1 ], [ %var1, %bb2 ].
			// We want to update only %var1 for basic block %bb1.
			phiNodeToUpdate.setOperand(i, &newValue);
		}
	}
}

/**
* @brief Update predecessors in PHI nodes in @a bb. @a oldBB is updated to
*        @a newBB.
*
* @param[in, out] bb Basic block with PHI nodes to update.
* @param[in] oldBB Old predecessor basic block in PHI node.
* @param[in] newBB New predecessor basic block in PHI node.
*/
void PHI2Seq::updatePredecessorsInPHINodes(BasicBlock &bb, BasicBlock &oldBB,
		BasicBlock &newBB) {
	auto it = bb.begin();
	while (PHINode *phiNodeToUpdate = dyn_cast<PHINode>(it)) {
		int ixB(phiNodeToUpdate->getBasicBlockIndex(&oldBB));
		assert(ixB != -1 && "Trying to update predecessor that doesn't exist");
		phiNodeToUpdate->setIncomingBlock(ixB, &newBB);
		++it;
	}
}

/**
* @brief Orders PHI nodes to correct sequential order.
*
* @param[in, out] bb Basic block to update.
* @param[in] nonCyclesDependResult Result of variable dependency analysis.
*/
void PHI2Seq::orderDependentPHINodes(BasicBlock &bb, const VarDependAnalysis::
		PHINodeVec &nonCyclesDependResult) {
	auto &instrList(bb.getInstList());

	// Ordering PHI nodes. Uses results of analysis.
	for (auto ri = nonCyclesDependResult.rbegin(),
			re = nonCyclesDependResult.rend(); ri != re; ++ri) {
		(*ri)->removeFromParent();
		instrList.push_front(*ri);
	}
}

} // namespace bin2llvmir
} // namespace retdec
