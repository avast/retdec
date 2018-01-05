/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/break_continue_return_optimizer.h
* @brief Removes statements following a break, continue, or return statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BREAK_CONTINUE_RETURN_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_BREAK_CONTINUE_RETURN_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Removes statements following a break, continue, or return statements.
*
* This optimizer removes statements following a break, continue, or return
* statements. For example, the
* following code
* @code
* switch (x) {
*     case 1:
*         ...
*         return
*         break
*     ...
* }
* @endcode
* can be optimized to
* @code
* switch (x) {
*     case 1:
*         ...
*         return
*     ...
* }
* @endcode
*
* If some of the statements following a break, continue, or return statement
* are goto targets, they are preserved.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class BreakContinueReturnOptimizer final: public FuncOptimizer {
public:
	BreakContinueReturnOptimizer(ShPtr<Module> module);

	virtual ~BreakContinueReturnOptimizer() override;

	virtual std::string getId() const override { return "BreakContinueReturn"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<BreakStmt> stmt) override;
	virtual void visit(ShPtr<ContinueStmt> stmt) override;
	virtual void visit(ShPtr<ReturnStmt> stmt) override;
	/// @}

	void removeSuccessorWhenAppropriate(ShPtr<Statement> stmt);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
