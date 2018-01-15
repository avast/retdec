/**
* @file src/llvmir2hll/optimizer/optimizers/c_cast_optimizer.cpp
* @brief Implementation of CCastOptimizer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <string>

#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/cast_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/optimizer/optimizers/c_cast_optimizer.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
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
CCastOptimizer::CCastOptimizer(ShPtr<Module> module):
	FuncOptimizer(module), optimized(false) {
		PRECONDITION_NON_NULL(module);
	}

/**
* @brief Destructs the optimizer.
*/
CCastOptimizer::~CCastOptimizer() {}

/**
* @brief Removes cast expression of source expression, if destination
*        expression doesn't need this cast.
*
* @param[in] dst Destination expression.
* @param[in] src Source expression.
*
* @note For the optimization of the casts we need to check the destination type
*       of the expression @a dst, type of the cast @a src and type of the
*       casted operand.
*/
ShPtr<Expression> CCastOptimizer::checkAndOptimize(ShPtr<Expression> dst,
		ShPtr<Expression> src) {
	// If source expression is the cast expression.
	if (ShPtr<CastExpr> srcCast = cast<CastExpr>(src)) {
		// Integer type optimization.
		// Implicit conversion to an integer type.
		if (ShPtr<IntType> dstType = cast<IntType>(dst->getType())) {
			if (ShPtr<IntType> srcType = cast<IntType>(src->getType())) {
				// Both are signed or unsigned.
				if (dstType->isSigned() == srcType->isSigned()) {
					if (cast<IntType>(srcCast->getOperand()->getType()) ||
							cast<FloatType>(srcCast->getOperand()->getType())) {
						// Cast expression removed.
						optimized = true;
						return srcCast->getOperand();
					}
				}
			}
		// Floating point type optimization.
		// Implicit conversion to float type.
		} else if (ShPtr<FloatType> dstFType = cast<FloatType>(dst->getType())) {
			if (ShPtr<FloatType> srcFType = cast<FloatType>(src->getType())) {
				if (cast<IntType>(srcCast->getOperand()->getType()) ||
						cast<FloatType>(srcCast->getOperand()->getType())) {
					// Cast expression removed.
					optimized = true;
					return srcCast->getOperand();
				}
			}
		}
	}
	optimized = false;
	return src;
}

// Visitors
void CCastOptimizer::visit(ShPtr<CallExpr> expr) {
	if (ShPtr<Variable> function = cast<Variable>(expr->getCalledExpr())) {
		// Searching the function. Argument types are needed.
		ShPtr<Function> func = module->getFuncByName(function->getName());
		if (func) {
			// Checks all expected and used arguments.
			const VarVector &params = func->getParams();
			// List of all destination and source arguments of found function.
			const ExprVector &args = expr->getArgs();
			ExprVector::const_iterator dst, edst; // destination iterators
			VarVector::const_iterator src, esrc; // source iterators
			// For each destination argument...
			for (dst = args.begin(), edst = args.end(),
					src = params.begin(), esrc = params.end();
					dst != edst && src != esrc; ++dst, ++src) {
				// Checking if is possible optimization
				// of destination arguments and source arguments.
				// Optimization.
				Expression::replaceExpression(*src,
						checkAndOptimize(*dst, *src));
			}
		}
	}
	FuncOptimizer::visit(expr);
}

void CCastOptimizer::visit(ShPtr<AssignStmt> stmt) {
	do {
		stmt->setRhs(checkAndOptimize(stmt->getLhs(), stmt->getRhs()));
	} while (optimized);
	FuncOptimizer::visit(stmt);
}

void CCastOptimizer::visit(ShPtr<VarDefStmt> stmt) {
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		do {
			stmt->setInitializer(checkAndOptimize(stmt->getVar(),
				stmt->getInitializer()));
		} while (optimized);
	}
	FuncOptimizer::visit(stmt);
}

void CCastOptimizer::visit(ShPtr<ReturnStmt> stmt) {
	if (ShPtr<Expression> retVal = stmt->getRetVal()) {
		do {
			stmt->setRetVal(checkAndOptimize(retVal, stmt->getRetVal()));
		} while (optimized);
	}
	FuncOptimizer::visit(stmt);
}

} // namespace llvmir2hll
} // namespace retdec
