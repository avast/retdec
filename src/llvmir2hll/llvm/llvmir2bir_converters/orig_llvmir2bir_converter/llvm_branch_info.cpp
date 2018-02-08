/**
* @file src/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_branch_info.cpp
* @brief Implementation of LLVMBranchInfo.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <vector>

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/llvm/llvm_support.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_branch_info.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_converter.h"
#include "retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/vars_handler.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"

using namespace retdec::llvm_support;

using retdec::utils::clear;
using retdec::utils::hasItem;

namespace retdec {
namespace llvmir2hll {

namespace {

// To produce deterministic results, we need to order the basic blocks
// by their name.
struct ByNameComparator {
	bool operator()(const llvm::BasicBlock *b1, const llvm::BasicBlock *b2) const {
		return b1->getName() < b2->getName();
	}
};
using BBToCountMap = std::map<llvm::BasicBlock *, unsigned, ByNameComparator>;

} // anonymous namespace

/**
* @brief Constructs a new informer.
*
* @param[in] converter Converter from LLVM values to values in the backend IR.
* @param[in] varsHandler Handler of variables created during decompilation.
*/
LLVMBranchInfo::LLVMBranchInfo(ShPtr<LLVMConverter> converter,
	ShPtr<VarsHandler> varsHandler):
		loopInfo(nullptr), converter(converter), varsHandler(varsHandler),
		loopStack(), branchStack() {}

/**
* @brief Destructs the variables handler.
*/
LLVMBranchInfo::~LLVMBranchInfo() {}

/**
* @brief Initializes the informer.
*
* @param[in] li Information about loops from LLVM.
*
* This function has to be called before the informer is used.
*/
void LLVMBranchInfo::init(llvm::LoopInfo *li) {
	loopInfo = li;
	loopStack.clear();
	clear(branchStack);
	branchStack.push(nullptr); // A bottom marker.
}

/**
* @brief Pushes @a bb onto the branch stack.
*/
void LLVMBranchInfo::branchStackPush(llvm::BasicBlock *bb) {
	branchStack.push(bb);
}

/**
* @brief Returns the topmost basic block from the branch stack.
*
* If there are no items in the stack, it returns the null pointer.
*/
llvm::BasicBlock *LLVMBranchInfo::branchStackTop() const {
	return branchStack.top();
}

/**
* @brief Returns the size of the branch stack.
*/
std::size_t LLVMBranchInfo::branchStackSize() const {
	return branchStack.size() - 1; // Do not include the bottom marker.
}

/**
* @brief Removes the topmost basic block from the branch stack.
*
* @par Preconditions
*  - the stack is not empty
*/
void LLVMBranchInfo::branchStackPop() {
	// Do not include the bottom marker.
	ASSERT_MSG(branchStack.size() > 1, "cannot pop from an empty stack");

	branchStack.pop();
}

/**
* @brief Returns @c true if we are currently generating a loop, @c false
*        otherwise.
*/
bool LLVMBranchInfo::generatingLoop() const {
	return !loopStack.empty();
}

/**
* @brief Marks the information that the loop @a l is being currently generated.
*
* This function has to be called whenever a new loop is started being
* generated; otherwise, some member functions might return incorrect
* information.
*
* @par Preconditions
*  - @a l is non-null
*/
void LLVMBranchInfo::startGeneratingLoop(llvm::Loop *l) {
	PRECONDITION_NON_NULL(l);

	loopStack.push_front(l);
}

/**
* @brief Marks the information that the currently generated loop has been
*        generated.
*
* This function has to be called whenever a loop has been generated; otherwise,
* some member functions might return incorrect information.
*/
void LLVMBranchInfo::endGeneratingLoop() {
	loopStack.pop_front();
}

/**
* @brief Returns @c true if @a bb is the header of @a loop, @c false otherwise.
*
* @par Preconditions
*  - @a bb and @a loop are non-null
*/
bool LLVMBranchInfo::isLoopHeader(llvm::BasicBlock *bb, llvm::Loop *loop) const {
	PRECONDITION_NON_NULL(bb);
	PRECONDITION_NON_NULL(loop);

	return loopInfo->isLoopHeader(bb) && loopInfo->getLoopFor(bb) == loop;
}

/**
* @brief Returns @c true if the given loop @a l can be optimized into a for
*        loop, @c false otherwise.
*
* "Optimized" means that instead of "while True", we can generate a for loop.
*
* @par Preconditions
*  - @a l is non-null
*/
bool LLVMBranchInfo::isOptimizableToForLoop(const llvm::Loop *l) const {
	PRECONDITION_NON_NULL(l);

	// We need to know the induction variable and the trip count.
	return l->getCanonicalInductionVariable() && getTripCount(l);
}

/**
* @brief Returns @c true if @a succ is the header of an inner loop in which @a
*        bb is, @c false otherwise.
*
* @par Preconditions
*  - both @a bb and @a succ are non-null
*/
bool LLVMBranchInfo::isSuccHeaderOfInnerLoop(llvm::BasicBlock *bb,
		llvm::BasicBlock *succ) const {
	PRECONDITION_NON_NULL(bb);
	PRECONDITION_NON_NULL(succ);

	if (loopStack.empty()) {
		return false;
	}

	auto innerLoop = loopStack.front();
	return innerLoop->getHeader() == succ;
}

/**
* @brief Returns @c true if @a succ is the header of an outer (NOT inner) loop
*        in which @a bb is, @c false otherwise.
*
* @par Preconditions
*  - both @a bb and @a succ are non-null
*/
bool LLVMBranchInfo::isSuccHeaderOfOuterLoop(llvm::BasicBlock *bb,
		llvm::BasicBlock *succ) const {
	PRECONDITION_NON_NULL(bb);
	PRECONDITION_NON_NULL(succ);

	if (loopStack.size() < 2) {
		return false;
	}

	// We need the second topmost loop.
	auto outerLoop = *(++loopStack.begin());
	return outerLoop->getHeader() == succ;
}

/**
* @brief Returns the common branch destination of @a bb1 and @a bb2.
*
* Given two basic blocks, @a bb1 and @a bb2, this function returns the common
* branch destination of branches in @a bb1 and @a bb2. If there is no common
* branch destination, the null pointer is returned.
*
* For example, lets have the following piece of code.
*
* @code
* if (cond) {
*    bb1:
*        ...
*        goto lab;
* } else {
*    bb2:
*        ...
*        goto lab;
* }
* lab:
*    ...
* @endcode
*
* Then, for @a bb1 and @a bb2, this function returns @c lab.
*
* @par Preconditions
*  - both @a bb1 and @a bb2 are non-null
*/
llvm::BasicBlock *LLVMBranchInfo::findCommonBranchDestination(
		llvm::BasicBlock *bb1, llvm::BasicBlock *bb2) const {
	PRECONDITION_NON_NULL(bb1);
	PRECONDITION_NON_NULL(bb2);

	// We're going to perform two simultaneous BFSs (breadth-first searches),
	// starting from bb1 and bb2, respectively. Therefore, we traverse the
	// control-flow graph, level by level, until we find a basic block which is
	// our common node. If we finish traversing the graph without encountering
	// a common basic block, then there is no such block.
	BFSQueue bfsQueue1, bfsQueue2;
	BBSet bfsProcessedBBs1, bfsProcessedBBs2;

	bfsQueue1.push(bb1);
	bfsQueue2.push(bb2);
	while (!bfsQueue1.empty() || !bfsQueue2.empty()) {
		llvm::BasicBlock *poppedBB1 = nullptr;
		if (!bfsQueue1.empty()) {
			poppedBB1 = bfsQueue1.front();
			bfsQueue1.pop();
		}

		llvm::BasicBlock *poppedBB2 = nullptr;
		if (!bfsQueue2.empty()) {
			poppedBB2 = bfsQueue2.front();
			bfsQueue2.pop();
		}

		// Check whether we've found the common branch destination.
		if (poppedBB1 == poppedBB2 ||
				hasItem(bfsProcessedBBs2, poppedBB1)) {
			return poppedBB1;
		} else if (hasItem(bfsProcessedBBs1, poppedBB2)) {
			return poppedBB2;
		}

		if (poppedBB1) {
			processAndPushBasicBlock(poppedBB1, bfsQueue1, bfsProcessedBBs1);
		}
		if (poppedBB2) {
			processAndPushBasicBlock(poppedBB2, bfsQueue2, bfsProcessedBBs2);
		}
	}

	// The common branch destination was not found.
	return nullptr;
}

/**
* @brief Processes the given basic block in a BFS search.
*
* Checks whether @a poppedBB hasn't been traversed yet. If it hasn't, the
* function pushes its successors to @a bfsQueue and marks it as a processed
* basic block in @a bfsProcessedBBs. The only pushed successors are the ones
* that are not the header of a loop in which @a poppedBB is. This ensures
* proper code emission.
*
* @par Preconditions
*  - @a poppedBB is non-null
*/
void LLVMBranchInfo::processAndPushBasicBlock(llvm::BasicBlock *poppedBB,
		BFSQueue &bfsQueue, BBSet &bfsProcessedBBs) const {
	PRECONDITION_NON_NULL(poppedBB);

	// Is the popped basic block a new one, i.e. we have not traversed it
	// yet? This ensures that the BFS algorithm will eventually end.
	if (!hasItem(bfsProcessedBBs, poppedBB)) {
		// It is, so add its successors (that are not the header of a loop in
		// which poppedBB is) into the queue.
		if (auto bi = llvm::dyn_cast<llvm::BranchInst>(poppedBB->getTerminator())) {
			auto numOfSuccessors = bi->getNumSuccessors();
			for (decltype(numOfSuccessors) i = 0; i < numOfSuccessors; ++i) {
				auto succ = bi->getSuccessor(i);
				if (!isSuccHeaderOfInnerLoop(poppedBB, succ)) {
					bfsQueue.push(succ);
				}
			}
		}

		bfsProcessedBBs.insert(poppedBB);
	}
}

/**
* @brief Returns @c true if a goto statement is necessary when branching from
*        @a srcBB to @a dstBB.
*
* @param[in] srcBB Source basic block from which we are jumping.
* @param[in] dstBB Destination basic block to which we are jumping.
*
* @par Preconditions
*  - both @a srcBB and @a dstBB are non-null
*  - a statement in the backend IR corresponding to @a dstBB has already been
*    emitted
*/
bool LLVMBranchInfo::isGotoNecessary(llvm::BasicBlock *srcBB,
		llvm::BasicBlock *dstBB) const {
	PRECONDITION_NON_NULL(srcBB);
	PRECONDITION_NON_NULL(dstBB);

	// If the source node is accessible form the destination node, we need a
	// goto.
	return isAccessible(srcBB, dstBB);
}

/**
* @brief Returns @c true if @a bb is accessible from the basic block @a from.
*
* @par Preconditions
*  - both @a bb and @a from are non-null
*/
bool LLVMBranchInfo::isAccessible(llvm::BasicBlock *bb, llvm::BasicBlock *from) const {
	PRECONDITION_NON_NULL(bb);
	PRECONDITION_NON_NULL(from);

	BBSet visitedBlocks;
	return isAccessibleImpl(bb, from, visitedBlocks);
}

/**
* @brief Tries to find a common destination of branches in the given switch
*        instruction.
*
* For example, the following switch statement has @c bb as the common
* destination of branches:
*
* @code
* switch (x) {
*     case 1:
*         ...
*         break
*     case 2:
*         ...
*         return
*     case 3:
*         ...
*         break
* }
* bb
* @endcode
*
* If there is no common destination, the null pointer is returned.
*
* @par Preconditions
*  - @a si is non-null
*/
llvm::BasicBlock *LLVMBranchInfo::findCommonSwitchDestination(
		llvm::SwitchInst *si) const {
	PRECONDITION_NON_NULL(si);

	// Case (1):
	// If the default switch branch has three or more predecessors, then it is
	// a common switch destination. Note that if it has one or two successors,
	// then it doesn't need to be a common switch destination.
	auto defaultBB = si->getDefaultDest();
	if (LLVMSupport::getNumberOfUniquePredecessors(defaultBB) >= 3) {
		return defaultBB;
	}

	// Case (2):
	// Get basic blocks of all cases.
	std::vector<llvm::BasicBlock *> switchCases;
	for (unsigned i = 2, e = si->getNumOperands(); i < e; i += 2) {
		switchCases.push_back(llvm::cast<llvm::BasicBlock>(si->getOperand(i+1)));
	}
	// Go through all the gathered basic blocks and check their terminators. If
	// their terminator is a branch, and this branch is not to the next case,
	// add all targets of the branch into a map. We then select a target with
	// the most predecessors.
	BBToCountMap primaryBranchTargets;
	for (unsigned i = 2, e = si->getNumOperands(); i < e; i += 2) {
		auto bb = llvm::cast<llvm::BasicBlock>(si->getOperand(i+1));
		auto bbTerm = bb->getTerminator();
		if (auto bi = llvm::dyn_cast<llvm::BranchInst>(bbTerm)) {
			for (unsigned j = 0; j < bi->getNumSuccessors(); ++j) {
				if ((i + 2) < e && bi->getSuccessor(j) != si->getOperand(i + 3)) {
					primaryBranchTargets[bi->getSuccessor(j)]++;
				}
			}
		}
	}
	// Add also the primary target of the default branch; however, do this only
	// if the target is not any of the case bodies.
	if (auto bi = llvm::dyn_cast<llvm::BranchInst>(defaultBB->getTerminator())) {
		for (unsigned j = 0; j < bi->getNumSuccessors(); ++j) {
			if (hasItem(switchCases, defaultBB)) {
				primaryBranchTargets[bi->getSuccessor(j)]++;
			}
		}
	}
	// Check which target was counted the most times and return it.
	llvm::BasicBlock *csd = nullptr; // common switch destination
	unsigned csdNumOfOccurrences = 0;
	for (auto &p: primaryBranchTargets) {
		if (p.second > csdNumOfOccurrences) {
			csd = p.first;
			csdNumOfOccurrences = p.second;
		}
	}
	return csd;
}

/**
* @brief Returns the trip count of the given loop @a l.
*
* Returns a loop-invariant constant integer indicating the number of times the
* loop will be executed. Note that this means that the backedge of the loop
* executes N-1 times. If the trip count cannot be determined, the function
* returns 0.
*
* The IndVarSimplify pass transforms loops to have a form that this
* function easily understands.
*/
ShPtr<ConstInt> LLVMBranchInfo::getTripCount(const llvm::Loop *l) const {
	// The implementation is based on the implementation of
	// Loop::getTripCount() from LLVM 2.8; since LLVM 3.1, it has been removed.
	// TODO Use SCEV for this purpose?
	//      https://llvm.org/viewvc/llvm-project?view=rev&revision=145262 says
	//      that this functionality has been moved to SCEV.

	// Canonical loops will end with a 'cmp ne i, v', where i is the incremented
	// canonical induction variable and v is the trip count of the loop.
	auto iv = l->getCanonicalInductionVariable();
	if (!iv || iv->getNumIncomingValues() != 2) {
		return {};
	}

	bool p0InLoop = l->contains(iv->getIncomingBlock(0));
	auto inc = iv->getIncomingValue(!p0InLoop);
	auto backedgeBlock = iv->getIncomingBlock(!p0InLoop);

	if (auto bi = llvm::dyn_cast<llvm::BranchInst>(backedgeBlock->getTerminator())) {
		if (bi->isConditional()) {
			if (auto ici = llvm::dyn_cast<llvm::ICmpInst>(bi->getCondition())) {
				if (ici->getOperand(0) == inc) {
					if (bi->getSuccessor(0) == l->getHeader()) {
						if (ici->getPredicate() == llvm::ICmpInst::ICMP_NE) {
							if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(
									ici->getOperand(1))) {
								return ConstInt::create(ci->getValue());
							}
						}
					} else if (ici->getPredicate() == llvm::ICmpInst::ICMP_EQ) {
						if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(
								ici->getOperand(1))) {
							return ConstInt::create(ci->getValue());
						}
					}
				}
			}
		}
	}

	// The trip count cannot be determined.
	return {};
}

/**
* @brief Returns the innermost loop that @a bb lives in.
*
* If @a bb is in no loop (for example, it is the entry node), the null pointer
* is returned.
*
* @par Preconditions
*  - @a bb is non-null
*/
llvm::Loop *LLVMBranchInfo::getLoopFor(const llvm::BasicBlock *bb) const {
	PRECONDITION_NON_NULL(bb);

	return loopInfo->getLoopFor(bb);
}

/**
* @brief Returns @c true if @a bb is accessible from the basic block @a from.
*
* @param[in] bb Searched basic block.
* @param[in] from Basic block from which we start the search.
* @param[in] visitedBlocks Set of already visited blocks.
*
* This function is an implementation of isAccessible(). It may recursively call
* itself.
*
* @par Preconditions
*  - both @a bb and @a from are non-null
*/
bool LLVMBranchInfo::isAccessibleImpl(llvm::BasicBlock *bb, llvm::BasicBlock *from,
		BBSet &visitedBlocks) const {
	PRECONDITION_NON_NULL(bb);
	PRECONDITION_NON_NULL(from);

	// Check whether we have found the statement we are looking for.
	if (bb == from) {
		return true;
	}

	// Check whether we have already checked this statement. If so, return to
	// avoid infinite recursion.
	if (hasItem(visitedBlocks, from)) {
		return false;
	}
	visitedBlocks.insert(from);

	//
	// Visit all successors of the source basic block.
	//

	// BranchInst.
	if (auto bi = llvm::dyn_cast<llvm::BranchInst>(from->getTerminator())) {
		auto numOfSuccessors = bi->getNumSuccessors();
		// It suffices if the basic block we are looking for is accessible
		// from one of the successors.
		for (decltype(numOfSuccessors) i = 0; i < numOfSuccessors; ++i) {
			llvm::BasicBlock *succ = bi->getSuccessor(i);
			if (isAccessibleImpl(bb, succ, visitedBlocks)) {
				return true;
			}
		}
		return false;
	}

	// SwitchInst.
	if (auto si = llvm::dyn_cast<llvm::SwitchInst>(from->getTerminator())) {
		// It suffices if the basic block we are looking for is accessible
		// from one of the switch cases.

		// First, check the default clause.
		if (isAccessibleImpl(bb, si->getDefaultDest(), visitedBlocks)) {
			return true;
		}

		// Then, check all other cases.
		for (unsigned i = 2, e = si->getNumOperands(); i < e; i += 2) {
			if (isAccessibleImpl(bb, llvm::cast<llvm::BasicBlock>(si->getOperand(i + 1)),
					visitedBlocks)) {
				return true;
			}
		}
	}

	// Other terminators, like the return or unreachable statements.
	return false;
}

} // namespace llvmir2hll
} // namespace retdec
