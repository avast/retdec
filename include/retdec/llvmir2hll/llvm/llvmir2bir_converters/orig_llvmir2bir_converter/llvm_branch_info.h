/**
* @file include/retdec/llvmir2hll/llvm/llvmir2bir_converters/orig_llvmir2bir_converter/llvm_branch_info.h
* @brief Supportive information about LLVM branches and loops.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LLVM_BRANCH_INFO_H
#define RETDEC_LLVMIR2HLL_LLVM_LLVMIR2BIR_CONVERTERS_ORIG_LLVMIR2BIR_CONVERTER_LLVM_BRANCH_INFO_H

#include <cstddef>
#include <deque>
#include <map>
#include <queue>
#include <set>
#include <stack>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/non_copyable.h"

namespace llvm {

class BasicBlock;
class Loop;
class LoopInfo;
class Module;
class SwitchInst;

} // namespace llvm

namespace retdec {
namespace llvmir2hll {

class ConstInt;
class LLVMConverter;
class Module;
class Statement;
class VarsHandler;

/**
* @brief Supportive information about LLVM branches and loops.
*
* This class contains supportive information about LLVM branches and loops. For
* example, it can compute the common branch destination of two basic blocks,
* which comes handy when generating if statements. It also provides several
* functions regarding loops.
*
* Before an instance of this class can be used, the init() member function has
* to be called. More specifically, this member function has to be called
* whenever a new function is being decompiled.
*
* Instances of this class have reference object semantics. This class is not
* meant to be subclassed.
*/
class LLVMBranchInfo final: private retdec::utils::NonCopyable {
public:
	LLVMBranchInfo(ShPtr<LLVMConverter> converter,
		ShPtr<VarsHandler> varsHandler);
	~LLVMBranchInfo();

	void init(llvm::LoopInfo *loopInfo);

	/// @name Manipulation with branch stack.
	/// @{
	void branchStackPush(llvm::BasicBlock *bb);
	llvm::BasicBlock *branchStackTop() const;
	std::size_t branchStackSize() const;
	void branchStackPop();
	/// @}

	/// @name Supportive information for loops.
	/// @{
	bool generatingLoop() const;
	void startGeneratingLoop(llvm::Loop *l);
	void endGeneratingLoop();

	bool isLoopHeader(llvm::BasicBlock *bb, llvm::Loop *loop) const;
	bool isOptimizableToForLoop(const llvm::Loop *l) const;
	bool isSuccHeaderOfInnerLoop(llvm::BasicBlock *bb,
		llvm::BasicBlock *succ) const;
	bool isSuccHeaderOfOuterLoop(llvm::BasicBlock *bb,
		llvm::BasicBlock *succ) const;

	ShPtr<ConstInt> getTripCount(const llvm::Loop *l) const;
	llvm::Loop *getLoopFor(const llvm::BasicBlock *bb) const;
	/// }@

	/// @name Supportive information for branches.
	/// @{
	llvm::BasicBlock *findCommonBranchDestination(llvm::BasicBlock *bb1,
		llvm::BasicBlock *bb2) const;
	llvm::BasicBlock *findCommonSwitchDestination(llvm::SwitchInst *si) const;
	bool isGotoNecessary(llvm::BasicBlock *srcBB,
		llvm::BasicBlock *dstBB) const;
	bool isAccessible(llvm::BasicBlock *bb, llvm::BasicBlock *from) const;
	/// }@

private:
	/// Set of basic blocks.
	using BBSet = std::set<llvm::BasicBlock *>;

	/// Queue for BFS (breadth-first search) traversals.
	using BFSQueue = std::queue<llvm::BasicBlock *>;

	/// Stack of loops that are being generated (this is needed to properly
	/// generate loop bodies).
	// Note to developers: We use std::deque instead of std::stack because
	//                     std::deque allows us to access the second topmost
	//                     symbol in an easier way.
	using LoopStack = std::deque<llvm::Loop *>;

	/// Stack of basic blocks to remember common branch destinations when
	/// generating nested if-else if statements.
	using BranchStack = std::stack<llvm::BasicBlock *>;

private:
	void processAndPushBasicBlock(llvm::BasicBlock *poppedBB,
		BFSQueue &bfsQueue, BBSet &bfsProcessedBBs) const;
	bool isAccessibleImpl(llvm::BasicBlock *bb, llvm::BasicBlock *from,
		BBSet &visitedBlocks) const;

private:
	/// Information about loops.
	llvm::LoopInfo *loopInfo;

	/// Type and values converter.
	ShPtr<LLVMConverter> converter;

	/// Handler of variables created during decompilation.
	ShPtr<VarsHandler> varsHandler;

	/// Stack of loops that are being generated (this is needed to properly
	/// generate loop bodies).
	LoopStack loopStack;

	/// Stack of basic blocks to remember common branch destinations when
	/// generating nested if-else if statements.
	BranchStack branchStack;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
