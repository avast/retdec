/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/simple_copy_propagation_optimizer.h
* @brief A simple version of the copy propagation optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLE_COPY_PROPAGATION_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_SIMPLE_COPY_PROPAGATION_OPTIMIZER_H

#include <unordered_set>

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class CFG;
class CFGBuilder;
class CallInfoObtainer;
class ValueAnalysis;
class VarUsesVisitor;

/**
* @brief A simple version of the copy propagation optimization.
*
* This is a simplified version of the copy propagation optimization (see
* CopyPropagationOptimizer). It performs a copy propagation only if the
* statement is of one of the following forms:
* @code
* // (1)
* a = expr (`expr` contains a function call)
* // ... `a` is used here (only once) and there are no other uses of `a` in the
*        function. There may be some statements between `a = expr` and the use of
*        `a`; in such a case, the optimization is done only if it does not
*        change the code behavior.
* @endcode
* or
* @code
* // (2)
* a = expr (`expr` is an arithmetical expression with no calls)
* // ... `a` is used here (may be several times) before variables used in the
* //     statement `a = expr` are modified, and apart from all the uses, there
* //     are no other uses of `a` in the function.
* @endcode
*
* The conditions (1) and (2) imply that `a` is just a temporary variable.
*
* TODO Currently, we optimize (2) only if `expr` is a variable. Otherwise,
*      in some cases, the result of the optimization is less readable than
*      the original code.
*
* The optimization is not performed when:
*  - the actual case differs from the cases (1) or (2) above
*  - `a` is a global variable
*  - `a` has assigned a name from debug information
*  - the expression contains array or struct accesses, dereferences, or address
*    operators
*  - the expression is a constant array, structure, or string
*  - the variables may be used indirectly (by a pointer)
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class SimpleCopyPropagationOptimizer final: public FuncOptimizer {
public:
	SimpleCopyPropagationOptimizer(Module* module, ValueAnalysis* va,
		CallInfoObtainer* cio);

	virtual std::string getId() const override { return "SimpleCopyPropagation"; }

private:
	virtual void doOptimization() override;
	virtual void runOnFunction(Function* func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(AssignStmt* stmt) override;
	virtual void visit(VarDefStmt* stmt) override;
	/// @}

	void tryOptimization(Statement* stmt);
	void tryOptimizationCase1(Statement* stmt, Variable* lhsVar,
		Expression* rhs);

private:
	/// Unordered set of variables.
	using VarUSet = std::unordered_set<Variable*>;

private:
	/// The used builder of CFGs.
	CFGBuilder* cfgBuilder = nullptr;

	/// Analysis of values.
	ValueAnalysis* va = nullptr;

	/// Obtainer of information about function calls.
	CallInfoObtainer* cio = nullptr;

	/// Visitor for obtaining uses of variables.
	VarUsesVisitor* vuv = nullptr;

	/// Global variables in @c module. This is here to speedup the optimization.
	/// By using this set, we do not have to ask @c module every time we need
	/// such information.
	VarSet globalVars;

	/// CFG of the currently optimized function.
	CFG* currCFG = nullptr;

	/// Set of variables that we have already tried to optimized.
	VarUSet triedVars;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
