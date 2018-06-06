/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/copy_propagation_optimizer.h
* @brief Copy propagation optimization.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_COPY_PROPAGATION_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_COPY_PROPAGATION_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class CallInfoObtainer;
class DefUseAnalysis;
class DefUseChains;
class UseDefAnalysis;
class UseDefChains;
class ValueAnalysis;
class VarUsesVisitor;

/**
* @brief Copy propagation optimization.
*
* This optimization replaces the occurrences of targets of direct assignments
* with their values. A direct assignment is a statement of the form <tt>x =
* y</tt>, which simply assigns the value of @c y to @c x.
*
* For example, the following code
* @code
* a = 1
* b = a
* return b
* @endcode
* can be replaced with
* @code
* return 1
* @endcode
* provided that certain conditions are met (e.g. @c a and @c b are non-global
* and are not used anywhere else).
*
* This optimization also removes dead assignments or variable definitions.
* These are assignments which assign a value into a variable which is then
* never used.
*
* For example, the following code
* @code
* a = 1
* return x
* @endcode
* can be replaced with
* @code
* return x
* @endcode
* provided that @c a is non-global.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class CopyPropagationOptimizer final: public FuncOptimizer {
public:
	CopyPropagationOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va,
		ShPtr<CallInfoObtainer> cio);

	virtual ~CopyPropagationOptimizer() override;

	virtual std::string getId() const override { return "CopyPropagation"; }

private:
	virtual void doOptimization() override;
	virtual void runOnFunction(ShPtr<Function> func) override;

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	/// @}

	void performOptimization();
	bool stmtOrUseHasBeenModified(ShPtr<Statement> stmt, const StmtSet &uses) const;
	void handleCaseEmptyUses(ShPtr<Statement> stmt, ShPtr<Variable> stmtLhsVar);
	void handleCaseSingleUse(ShPtr<Statement> stmt, ShPtr<Variable> stmtLhsVar,
		ShPtr<Statement> use);
	void handleCaseMoreThanOneUse(ShPtr<Statement> stmt, ShPtr<Variable> stmtLhsVar,
		const StmtSet &uses);
	bool shouldBeIncludedInDefUseChains(ShPtr<Variable> var);

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;

	/// Obtainer of information about function calls.
	ShPtr<CallInfoObtainer> cio;

	/// Visitor for obtaining uses of variables.
	ShPtr<VarUsesVisitor> vuv;

	/// Def-use analysis.
	ShPtr<DefUseAnalysis> dua;

	/// Use-def analysis.
	ShPtr<UseDefAnalysis> uda;

	/// Def-use chains.
	ShPtr<DefUseChains> ducs;

	/// Use-def chains.
	ShPtr<UseDefChains> udcs;

	/// Global variables in @c module. This is here to speedup the traversal. By
	/// using this set, we do not have to ask @c module every time we need such
	/// information.
	VarSet globalVars;

	/// Set of statements that should be removed entirely.
	StmtSet toEntirelyRemoveStmts;

	/// Set of assign/variable-defining statements that should be removed, but
	/// function calls should be preserved.
	StmtSet toRemoveStmtsPreserveCalls;

	/// Set of statements that have been modified (altered or removed).
	StmtSet modifiedStmts;

	/// Has the code changed?
	bool codeChanged;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
