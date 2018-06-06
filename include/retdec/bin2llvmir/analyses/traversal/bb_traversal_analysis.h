/**
* @file include/retdec/bin2llvmir/analyses/traversal/bb_traversal_analysis.h
* @brief Post-order traversal analysis for basic blocks.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_BB_TRAVERSAL_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_BB_TRAVERSAL_ANALYSIS_H

#include <llvm/IR/BasicBlock.h>

#include "retdec/bin2llvmir/analyses/traversal/traversal_analysis.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Post-order traversal analysis for basic blocks.
*
* Before use this analysis you have to run @c doBBsAnalysis().
*
* For this example below analysis returns basic blocks in this order: left,
* right and bb. As you can see in post-order traversal.
* @code
* bb:
*   br i1 1, label %left, label %right
* left:
*   ret i32 0
* right:
*   ret i32 0
* @endcode
*
* Basic blocks can be in strongly connected component. Example below shows this
* situation. In this situation is not possible to do a correct post-order. It is
* because basic blocks sccbb and sccbb1 creates strongly connected component.
* You can use here two types of traversal:
* -# When you use for getting next block only method @c getNextBB(), than you
*   get basic blocks in this order: end, sccbb1, sccbb, bb. All basic blocks
*   only once.
* -# When you are sure by @c isNextInSCC() that the next basic block is in
*   strongly connected component than you can use @c getNextBBInSCC(). This
*   method causes iterating through strongly connected component until you use
*   method @c stopIteratingSCC(). Then use @c getNextBB() which returns the next
*   basic block which is out from iterated strongly connected component.
*
*   For example order:
*     -# @c getNextBB() - returns end.
*     -# @c isNextInSCC() => returns @c true then @c getNextBBInSCC() -
*        returns sccb1.
*     -# 2 times @c getNextBBInSCC() - returns sccbb and sccbb1.
*     -# @c stopIteratingSCC() and @c getNextBB() - returns bb.
* @code
* bb:
*   br label %sccbb
* sccbb:
*   br label %sccbb1
* sccbb1:
*   br i1 1, label %bb, label %end
* end:
*   ret i32 0
* @endcode
*/
class BBTraversalAnalysis: public TraversalAnalysis {
public:
	BBTraversalAnalysis();
	~BBTraversalAnalysis();

	void doBBsAnalysis(llvm::Function &func);
	llvm::BasicBlock *getNextBB();
	llvm::BasicBlock *getNextBBInSCC();

private:
	Node *processBBsInSCC(const std::vector<llvm::BasicBlock*> &sccBBs, Node *prevNode);
	Node *processBBNotInSCC(const std::vector<llvm::BasicBlock*> &sccBBs, Node *prevNode);

	void print();
};

} // namespace bin2llvmir
} // namespace retdec

#endif
