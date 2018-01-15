/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/var_use_cfg_traversal.h
* @brief A CFG traversal that checks whether a variable is defined/modified
*        prior to every read access to it in a function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_VAR_USE_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_VAR_USE_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;
class Variable;

/**
* @brief A CFG traversal that checks whether a variable is defined/modified
*        prior to every read access to it in a function.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class VarUseCFGTraversal final: public CFGTraversal {
public:
	~VarUseCFGTraversal();

	static bool isDefinedPriorToEveryAccess(ShPtr<Variable> var,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va);

private:
	/// Variable whose definition/modification is looked for.
	ShPtr<Variable> var;

	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

private:
	VarUseCFGTraversal(ShPtr<Variable> var,
		ShPtr<CFG> cfg, ShPtr<ValueAnalysis> va);

	virtual bool visitStmt(ShPtr<Statement> stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
