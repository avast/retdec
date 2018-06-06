/**
* @file include/retdec/bin2llvmir/analyses/traversal/func_traversal_analysis.h
* @brief Post-order traversal analysis for functions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_FUNC_TRAVERSAL_ANALYSIS_H
#define RETDEC_BIN2LLVMIR_ANALYSES_TRAVERSAL_FUNC_TRAVERSAL_ANALYSIS_H

#include <llvm/Analysis/CallGraphSCCPass.h>

#include "retdec/bin2llvmir/analyses/traversal/traversal_analysis.h"

namespace retdec {
namespace bin2llvmir {

/**
* @brief Post-order traversal analysis for functions.
*
* Before use this analysis you have to run @c doFuncsAnalysis().
*
* For this example below analysis returns functions in this order: funcFirst,
* funcSecond and funcTop. As you can see in post-order traversal.
* @code
* define void @funcTop() {
*   call void @funcFirst()
*   call void @funcSecond()
*   ret void
* }
*
* define void @funcFirst() {
*   ret void
* }
*
* define void @funcSecond() {
*   ret void
* }
* @endcode
*
* Functions can be in strongly connected component. Example below shows this
* situation. In this situation is not possible to do a correct post-order. It is
* because functions sccFunc and sccFunc1 creates strongly connected component.
* You can use here two types of traversal:
* -# When you use for getting next function only method @c getNextFunc(), than
*    you get functions in this order: endFunc, sccFunc1, sccFunc, funcTop. All
*    functions only once.
* -# When you are sure by @c isNextInSCC() that the next function is in strongly
*    connected component than you can use @c getNextFuncInSCC(). This method
*    causes iterating through strongly connected component until you use method
*    @c stopIteratingSCC(). Then use @c getNextFunc() which returns the next
*    function which is out from iterated strongly connected component.
*
*    For example order:
*    -# @c getNextFunc() - returns endFunc.
*    -# @c isNextInSCC() => returns @c true then @c getNextFuncInSCC() -
*       returns sccFunc1.
*    -# 2 times @c getNextFuncInSCC() - returns sccFunc and sccFunc1.
*    -# @c stopIteratingSCC() and @c getNextFunc() - returns funcTop.
* @code
* define void @funcTop() {
*   call void @sccFunc()
*   ret void
* }
*
* define void @sccFunc() {
*   call void @sccFunc1()
*   ret void
* }
*
* define void @sccFunc1() {
*   call void @sccFunc()
*   call void @endFunc()
*   ret void
* }
*
* define void @endFunc() {
*   ret void
* }
* @endcode
*/
class FuncTraversalAnalysis: public TraversalAnalysis {
public:
	FuncTraversalAnalysis();
	~FuncTraversalAnalysis();

	void doFuncsAnalysis(llvm::CallGraph &callGraph);
	llvm::Function *getNextFunc();
	llvm::Function *getNextFuncInSCC();

private:
	Node *processFuncsInSCC(const std::vector<llvm::CallGraphNode*> &callNodesVec,
		Node *prevNode);
	Node *processFuncNotInSCC(const std::vector<llvm::CallGraphNode*> &callNodesVec,
		Node *prevNode);

	void print();
};

} // namespace bin2llvmir
} // namespace retdec

#endif
