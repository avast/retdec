/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/empty_stmt_optimizer.h
* @brief Removes empty statements.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_EMPTY_STMT_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_EMPTY_STMT_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Removes empty statements.
*
* This optimizer removes all empty statements.
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class EmptyStmtOptimizer final: public FuncOptimizer {
public:
	EmptyStmtOptimizer(ShPtr<Module> module);

	virtual ~EmptyStmtOptimizer() override;

	virtual std::string getId() const override { return "EmptyStmt"; }

private:
	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<EmptyStmt> stmt) override;
	/// @}
};

} // namespace llvmir2hll
} // namespace retdec

#endif
