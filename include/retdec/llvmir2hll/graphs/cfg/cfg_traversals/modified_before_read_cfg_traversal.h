/**
* @file include/retdec/llvmir2hll/graphs/cfg/cfg_traversals/modified_before_read_cfg_traversal.h
* @brief A CFG traversal that checks whether a variable is modified prior to
*        every read access to it starting from a given statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_MODIFIED_BEFORE_READ_CFG_TRAVERSAL_H
#define RETDEC_LLVMIR2HLL_GRAPHS_CFG_CFG_TRAVERSALS_MODIFIED_BEFORE_READ_CFG_TRAVERSAL_H

#include "retdec/llvmir2hll/graphs/cfg/cfg_traversal.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class Statement;
class ValueAnalysis;
class Variable;

/**
* @brief A CFG traversal that checks whether a variable is modified prior to
*        every read access to it starting from a given statement.
*
* Instances of this class have reference object semantics. This is a concrete
* traverser which should not be subclassed.
*/
class ModifiedBeforeReadCFGTraversal final: public CFGTraversal {
public:
	static bool isModifiedBeforeEveryRead(Variable* var,
		Statement* startStmt, CFG* cfg, ValueAnalysis* va,
		CallInfoObtainer* cio);

private:
	ModifiedBeforeReadCFGTraversal(Variable* var,
		CFG* cfg, ValueAnalysis* va, CallInfoObtainer* cio);

	virtual bool visitStmt(Statement* stmt) override;
	virtual bool getEndRetVal() const override;
	virtual bool combineRetVals(bool origRetVal, bool newRetVal) const override;

private:
	/// Variable whose modification is looked for.
	Variable* var = nullptr;

	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// Obtainer of information about function calls.
	CallInfoObtainer* cio = nullptr;

	/// Was the variable modified before every read?
	bool wasModifiedBeforeEveryRead;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
