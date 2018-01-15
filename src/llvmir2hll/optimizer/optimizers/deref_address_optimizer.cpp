/**
* @file src/llvmir2hll/optimizer/optimizers/deref_address_optimizer.cpp
* @brief Implementation of DerefAddressOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/deref_address_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new optimizer.
*
* @param[in] module Module to be optimized.
*
* @par Preconditions
*  - @a module is non-null
*/
DerefAddressOptimizer::DerefAddressOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
DerefAddressOptimizer::~DerefAddressOptimizer() {}

void DerefAddressOptimizer::visit(ShPtr<DerefOpExpr> expr) {
	expr->getOperand()->accept(this);

	// Check whether we're dereferencing an address operator. If so, then
	// remove these two dereference+address operators.
	if (ShPtr<AddressOpExpr> addressOpExpr = cast<AddressOpExpr>(
			expr->getOperand())) {
		Expression::replaceExpression(expr, addressOpExpr->getOperand());
	}
}

} // namespace llvmir2hll
} // namespace retdec
