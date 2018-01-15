/**
* @file src/llvmir2hll/optimizer/optimizers/remove_all_casts_optimizer.cpp
* @brief Implementation of RemoveAllCastsOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/optimizer/optimizers/remove_all_casts_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/utils/ir.h"

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
RemoveAllCastsOptimizer::RemoveAllCastsOptimizer(ShPtr<Module> module):
	FuncOptimizer(module) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
RemoveAllCastsOptimizer::~RemoveAllCastsOptimizer() {}

void RemoveAllCastsOptimizer::visit(ShPtr<BitCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<ExtCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<TruncCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<FPToIntCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<IntToFPCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<IntToPtrCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

void RemoveAllCastsOptimizer::visit(ShPtr<PtrToIntCastExpr> expr) {
	FuncOptimizer::visit(expr);
	removeCast(expr);
}

/**
* @brief Removes the given cast.
*/
void RemoveAllCastsOptimizer::removeCast(ShPtr<CastExpr> castExpr) {
	ShPtr<Expression> nonCastExpr(skipCasts(castExpr));
	Expression::replaceExpression(castExpr, nonCastExpr);
}

} // namespace llvmir2hll
} // namespace retdec
