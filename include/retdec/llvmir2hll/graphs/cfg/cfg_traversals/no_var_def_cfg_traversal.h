/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/no_var_def_cfg_traversal.h
* @brief A CFG traversal that checks whether no variable in a given set is
*        defined/modified between a start statement and a set of end statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_NO_VAR_DEF_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_NO_VAR_DEF_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;
class Variable;

/**
* @brief A CFG traversal that checks whether no variable in a given set is
*        defined/modified between a start statement and a set of end statements.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class NoVarDefCFGTraversal final: public CFGTraversal {
public:
	static bool noVarIsDefinedBetweenStmts(Statement* start,
		const StmtSet &ends, const VarSet &vars, CFG* cfg,
		ValueAnalysis* va);

private:
	/// Statements at which we should end the traversal.
	const StmtSet &ends;

	/// Variables for whose definition/modification we're looking for.
	const VarSet &vars;

	/// Analysis of values.
	ValueAnalysis* va = nullptr;

private:
	NoVarDefCFGTraversal(CFG* cfg, const StmtSet &ends,
		const VarSet &vars, ValueAnalysis* va);

	virtual bool visitStmt(Statement* stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
