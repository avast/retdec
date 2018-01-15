/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_def_cfg_traversal.h
* @brief A CFG traversal that checks whether a variable is defined/modified
*        between two statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_VAR_DEF_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_VAR_DEF_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class Statement;
class ValueAnalysis;
class VarDefCFGTraversal;
class Variable;

/**
* @brief A CFG traversal that checks whether a variable is defined/modified
*        between two statements.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class VarDefCFGTraversal final: public CFGTraversal {
public:
	~VarDefCFGTraversal();

	static bool isVarDefBetweenStmts(const VarSet &vars,
		ShPtr<Statement> start, ShPtr<Statement> end, ShPtr<CFG> cfg,
		ShPtr<ValueAnalysis> va);

private:
	/// Variables for whose definition/modification we're looking for.
	const VarSet &vars;

	/// Statement at which we should end the traversal.
	ShPtr<Statement> end;

	/// The used analysis of values.
	ShPtr<ValueAnalysis> va;

private:
	VarDefCFGTraversal(ShPtr<CFG> cfg, const VarSet &vars,
		ShPtr<Statement> end, ShPtr<ValueAnalysis> va);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
