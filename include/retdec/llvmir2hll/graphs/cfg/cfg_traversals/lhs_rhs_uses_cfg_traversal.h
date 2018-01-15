/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/lhs_rhs_uses_cfg_traversal.h
* @brief A CFG traversal that for an assign statement @c S returns the uses of
*        its left-hand side such that there are no uses of its right-hand side
*        before them.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_LHS_RHS_USES_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_LHS_RHS_USES_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class Statement;
class ValueAnalysis;

/**
* @brief A CFG traversal that for an assign statement @c S returns the uses of
*        its left-hand side such that there are no modifications of variables
*        used in @c S before them.
*
* This traverser is meant to be used in SimpleCopyPropagationOptimizer, see its
* description for more details.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class LhsRhsUsesCFGTraversal final: public CFGTraversal {
public:
	~LhsRhsUsesCFGTraversal();

	static StmtSet getUses(ShPtr<Statement> stmt, ShPtr<CFG> cfg,
		ShPtr<ValueAnalysis> va, ShPtr<CallInfoObtainer> cio);

private:
	/// Original statement.
	ShPtr<Statement> origStmt;

	/// The left-hand side of the original statement.
	ShPtr<Variable> origLhsVar;

	/// The set of variables used in the right-hand side of the original
	/// statement.
	const VarSet &origRhsVars;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Obtainer of information about function calls.
	ShPtr<CallInfoObtainer> cio;

	/// Uses of the variable defined in @c origStmt.
	StmtSet uses;

private:
	LhsRhsUsesCFGTraversal(ShPtr<Statement> stmt, ShPtr<Variable> origLhsVar,
		const VarSet &origRhsVars, ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
