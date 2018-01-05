/**
* @file src/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer.cpp
* @brief Implementation of CArrayArgOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/c_array_arg_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Returns the new argument if the given argument can be optimized, the
*        null pointer otherwise.
*/
ShPtr<Expression> canArgBeOptimized(ShPtr<Expression> arg) {
	// We have to check that the argument is of the form
	//
	//    &x[0]
	//
	// If this is so, we return x, which is the new argument.

	ShPtr<AddressOpExpr> addressOpExpr(cast<AddressOpExpr>(arg));
	if (!addressOpExpr) {
		return ShPtr<Expression>();
	}

	ShPtr<ArrayIndexOpExpr> arrayIndexOpExpr(cast<ArrayIndexOpExpr>(
		addressOpExpr->getOperand()));
	if (!arrayIndexOpExpr) {
		return ShPtr<Expression>();
	}

	ShPtr<Variable> var(cast<Variable>(arrayIndexOpExpr->getBase()));
	if (!var) {
		return ShPtr<Expression>();
	}

	ShPtr<ConstInt> index(cast<ConstInt>(arrayIndexOpExpr->getIndex()));
	if (!index || !index->isZero()) {
		return ShPtr<Expression>();
	}

	return var;
}

} // anonymous namespace

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
CArrayArgOptimizer::CArrayArgOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
CArrayArgOptimizer::~CArrayArgOptimizer() {}

void CArrayArgOptimizer::visit(ShPtr<CallExpr> expr) {
	OrderedAllVisitor::visit(expr);

	// Check each argument whether it can be optimized, and if so, do it.
	for (const auto &arg : expr->getArgs()) {
		if (ShPtr<Expression> newArg = canArgBeOptimized(arg)) {
			expr->replaceArg(arg, newArg);
		}
	}
}

} // namespace llvmir2hll
} // namespace retdec
