/**
* @file include/retdec/llvmir2hll/optimizer/optimizers/aggressive_deref_optimizer.h
* @brief Optimizes dereferences of integer values.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AGGRESSIVE_DEREF_OPTIMIZER_H
#define RETDEC_LLVMIR2HLL_OPTIMIZER_OPTIMIZERS_AGGRESSIVE_DEREF_OPTIMIZER_H

#include "retdec/llvmir2hll/optimizer/func_optimizer.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Optimizes dereferences of integer values.
*
* Currently, this optimizer removes assign or variable-defining statements that
* access memory locations through an integer. For example, all the following
* statements are removed:
* @code
* *(56778) = 5;
* a = *(int32_t *)56780;
* a = *(i + 5); // i here is of an integral type
* @endcode
*
* Instances of this class have reference object semantics.
*
* This is a concrete optimizer which should not be subclassed.
*/
class AggressiveDerefOptimizer final: public FuncOptimizer {
public:
	AggressiveDerefOptimizer(ShPtr<Module> module);

	virtual ~AggressiveDerefOptimizer() override;

	virtual std::string getId() const override { return "AggressiveDeref"; }

private:
	void tryToOptimizeStmt(ShPtr<Statement> stmt, ShPtr<Expression> lhs,
		ShPtr<Expression> rhs);

	/// @name Visitor Interface
	/// @{
	using OrderedAllVisitor::visit;
	virtual void visit(ShPtr<DerefOpExpr> expr) override;
	virtual void visit(ShPtr<AssignStmt> stmt) override;
	virtual void visit(ShPtr<VarDefStmt> stmt) override;
	/// @}

private:
	// Have we found a dereference of an integer?
	bool intDerefFound;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
