/**
* @file src/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer.cpp
* @brief Implementation of DerefToArrayIndexOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/deref_to_array_index_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module @a Module to be optimized.
*
* @par Preconditions
*  - @a module and @a va are non-null
*/
DerefToArrayIndexOptimizer::DerefToArrayIndexOptimizer(ShPtr<Module> module):
		Optimizer(module) {
	PRECONDITION_NON_NULL(module);
}

/**
* @brief Destructs the optimizer.
*/
DerefToArrayIndexOptimizer::~DerefToArrayIndexOptimizer() {}

void DerefToArrayIndexOptimizer::doOptimization() {
	// Visit all global variables and their initializers.
	for (auto i = module->global_var_begin(), e = module->global_var_end();
			i != e; ++i) {
		(*i)->accept(this);
	}

	// Visit all functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(this);
	}
}

void DerefToArrayIndexOptimizer::visit(ShPtr<DerefOpExpr> expr) {
	// First, visit (and possibly optimize) nested expressions.
	Optimizer::visit(expr);

	ShPtr<AddOpExpr> addOpExpr(cast<AddOpExpr>(expr->getOperand()));
	if (!addOpExpr) {
		return;
	}

	Maybe<BaseAndIndex> baseAndIndex(getBaseAndIndexFromExprIfPossible(
		addOpExpr));
	if (!baseAndIndex) {
		// Can't optimize. Expression is not like:
		// *(a + 5 - vice versa) or *(a[2] + 2 - vice versa).
		return;
	}

	replaceDerefWithArrayIndex(expr, baseAndIndex.get());
}

/**
* @brief Try to get the base and index for new ArrayIndexOpExpr from @a expr.
*
* @param[in] expr Expression from which is trying to get base and index.
*
* @return <tt>Just(BaseAndIndex)</tt> if the @a expr can be parsed to base and
*         index. Otherwise <tt>Nothing<BaseAndIndex>()</tt>.
*/
Maybe<DerefToArrayIndexOptimizer::BaseAndIndex> DerefToArrayIndexOptimizer::
		getBaseAndIndexFromExprIfPossible(ShPtr<AddOpExpr> expr) {
	BaseAndIndex baseAndIndex;
	ShPtr<Expression> firstOp(expr->getFirstOperand());
	ShPtr<Expression> secOp(expr->getSecondOperand());

	// One of the operand must be ConstInt.
	if (isa<ConstInt>(firstOp)) {
		baseAndIndex.index = firstOp;
	} else if (isa<ConstInt>(secOp)) {
		baseAndIndex.index = secOp;
	} else {
		return Nothing<BaseAndIndex>();
	}

	// One of the operand must be Variable or ArrayIndexOpExpr or
	// StructIndexOpExpr.
	if (isa<Variable>(firstOp) || isa<ArrayIndexOpExpr>(firstOp) ||
			isa<StructIndexOpExpr>(firstOp)) {
		baseAndIndex.base = firstOp;
	} else if (isa<Variable>(secOp) || isa<ArrayIndexOpExpr>(secOp) ||
			isa<StructIndexOpExpr>(secOp)) {
		baseAndIndex.base = secOp;
	} else {
		return Nothing<BaseAndIndex>();
	}

	return Just(baseAndIndex);
}

/**
* @brief Replace @a oldExpr with ArrayIndexOpExpr which is created by @a base
*        @a index.
*
* @param[in] oldExpr DerefOpExpr that will be replaced.
* @param[in] baseAndIndex Base and index to new ArrayIndexOpExpr.
*/
void DerefToArrayIndexOptimizer::replaceDerefWithArrayIndex(ShPtr<DerefOpExpr>
		oldExpr, const BaseAndIndex &baseAndIndex) {
	ShPtr<ArrayIndexOpExpr> arrayIndexOp(ArrayIndexOpExpr::create(
		baseAndIndex.base, baseAndIndex.index));
	Expression::replaceExpression(oldExpr, arrayIndexOp);
}

} // namespace llvmir2hll
} // namespace retdec
