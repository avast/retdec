/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/unreachable_code_optimizer.h
* @brief Elimination of unreachable code.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_UNREACHABLE_CODE_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_UNREACHABLE_CODE_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ValueAnalysis;

/**
* @brief Elimination of unreachable code.
*
* This optimizer eliminates code that appears before calls of functions which
* never returns. More precisely, it replaces the code after the call with
* UnreachableStmt, and removes useless code before the call.
*
* For example, the following code
* @code
* int func() {
*     g = 5;
*     exit(1);
*     apple = 5;
*     return 0;
* }
* @endcode
* is optimized into
* @code
* int func() {
*     exit(1);
*     // UNREACHABLE
* }
* @endcode
*
* To specify the set of functions that never returns, we use Semantics (run @c
* module->getSemantics() to obtain the used semantics).
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class UnreachableCodeOptimizer final: public FuncOptimizer {
public:
	UnreachableCodeOptimizer(ShPtr<Module> module, ShPtr<ValueAnalysis> va);

	virtual ~UnreachableCodeOptimizer() override;

	virtual std::string getId() const override { return "UnreachableCode"; }

private:
	virtual void doOptimization() override;

	bool isCallOfDeclaredFuncThatNeverReturns(ShPtr<CallStmt> stmt) const;
	bool isSuccessorUnreachable(ShPtr<CallStmt> stmt) const;
	void performOptimization(ShPtr<CallStmt> stmt);

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<CallStmt> stmt) override;
	/// @}

private:
	/// Analysis of values.
	ShPtr<ValueAnalysis> va;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
