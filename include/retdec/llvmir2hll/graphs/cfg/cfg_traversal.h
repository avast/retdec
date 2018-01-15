/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversal.h
* @brief A base class of all CFG traversals.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/utils/non_copyable.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief A base class of all CFG traversals.
*
* A concrete CFG traverser has to implement all purely abstract member
* functions.
*
* This class is based on the "Template method" design pattern.
*
* Instances of this class have reference object semantics.
*/
class CFGTraversal: private retdec::utils::NonCopyable {
protected:
	CFGTraversal(ShPtr<CFG> cfg, bool defaultCurrRetVal);
	// The destructor is protected and non-virtual on a purpose. Indeed,
	// concrete CFG traversers are not meant to be used by a pointer to the
	// base class.
	~CFGTraversal();

	bool getCurrRetVal() const;
	bool performTraversal(ShPtr<Statement> startStmt);
	bool performTraversalFromSuccessors(ShPtr<Statement> stmt);
	bool performReverseTraversal(ShPtr<Statement> startStmt);
	bool performReverseTraversalFromPredecessors(ShPtr<Statement> stmt);

	/**
	* @brief Visits the given statement @a stmt.
	*
	* @a return @c true if the traversing should continue, @c false otherwise.
	*
	* Note: @c checkedStmts is modified in CFGTraversal, so it is not necessary
	* for the implementation of this function to add @a stmt to @c
	* checkedStmts.
	*
	* If you want the traversal to end prematurely, set the stopTraversal
	* variable to @c true. Otherwise, if you just return @c false, the
	* traversal may still continue from other branches because of recursion.
	*/
	virtual bool visitStmt(ShPtr<Statement> stmt) = 0;

	/**
	* @brief Returns the value that should be returned when an end of the
	*        traversal is reached.
	*
	* For example, the end may mean the end node of the CFG or a statement that
	* has already been traversed.
	*/
	virtual bool getEndRetVal() const = 0;

	/**
	* @brief Computes a new return value from the original return value (@a
	*        origRetVal) and the new return value (@a newRetVal).
	*/
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const = 0;

protected:
	/// CFG that is being traversed.
	ShPtr<CFG> cfg;

	/// Statements that have been checked (to prevent looping).
	StmtUSet checkedStmts;

	/// Current return value of visitStmt().
	bool currRetVal;

	/// Should the traversal be stopped?
	bool stopTraversal;

private:
	bool performTraversalImpl(ShPtr<CFG::Node> startNode,
		CFG::stmt_iterator startStmtIter);
	bool performReverseTraversalImpl(ShPtr<CFG::Node> startNode,
		CFG::stmt_reverse_iterator startStmtRIter);
	bool traverseNodeSuccessors(ShPtr<CFG::Node> node);
	bool traverseNodePredecessors(ShPtr<CFG::Node> node);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
