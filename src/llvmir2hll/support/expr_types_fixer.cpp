/**
* @file src/llvmir2hll/support/expr_types_fixer.cpp
* @brief A visitor for fixing the types in the IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cstddef>

#include "retdec/llvmir2hll/analysis/expr_types_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/expr_types_fixer.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*/
ExprTypesFixer::ExprTypesFixer():
	OrderedAllVisitor() {}

/**
* @brief Destructs the visitor.
*/
ExprTypesFixer::~ExprTypesFixer() {}

/**
* @brief Sets the probably types based on statistics. Statistics are from
*        @c ExprTypesAnalysis.
*
* @param[in] module Searched module.
*/
void ExprTypesFixer::setProbablyTypes(ShPtr<Module> module) {
	// Create Analysis of integer types.
	ShPtr<ExprTypesAnalysis> exprTypesAnalysis(ExprTypesAnalysis::create());
	bool changed = true;
	while (changed) {
		changed = false;
		// The analysis returns statistics about variables in map.
		ExprTypesAnalysis::ExprTagsMap exprTagsMap =
				exprTypesAnalysis->analyzeExprTypes(module);
		// Check statistics about all variables and fix their types to correct
		// signed if expected.
		for (const auto &p : exprTagsMap) {
			ShPtr<Expression> expr = p.first;
			// Get statistics about expression - how many times it is used as
			// signed.
			std::size_t isSigned = exprTypesAnalysis->getCountOfTag(
				expr, ExprTypesAnalysis::ExprTag::Signed);
			// Get statistics about expression - how many times it is used as
			// unsigned.
			std::size_t isUnsigned = exprTypesAnalysis->getCountOfTag(
				expr, ExprTypesAnalysis::ExprTag::Unsigned);
			// We can change the type of a variable.
			if (ShPtr<Variable> var = cast<Variable>(expr)) {
				if (ShPtr<IntType> type = cast<IntType>(var->getType())) {
					// Evaluation of statistics and fixing of type.
					if ((isSigned > isUnsigned) && type->isUnsigned()) {
						changed = true;
						var->setType(IntType::create(type->getSize(), true));
					} else if ((isSigned <= isUnsigned) && type->isSigned()) {
						changed = true;
						var->setType(IntType::create(type->getSize(), false));
					}
				}
			// We can change the type of a constant.
			} else if (ShPtr<ConstInt> constant = cast<ConstInt>(expr)) {
				if (ShPtr<IntType> type = cast<IntType>(constant->getType())) {
					// Evaluation of statistics and fixing of type.
					if ((isSigned > isUnsigned) && constant->isUnsigned()) {
						changed = true;
						llvm::APSInt val = constant->getValue();
						val.setIsSigned(true);
						Expression::replaceExpression(expr,
							ConstInt::create(val));
					} else if ((isSigned <= isUnsigned) && constant->isSigned()) {
						changed = true;
						llvm::APSInt val = constant->getValue();
						val.setIsUnsigned(true);
						Expression::replaceExpression(expr,
							ConstInt::create(val));
					}
				}
			// We can change the type of a CalledExpr of CallExpr.
			} else if (ShPtr<CallExpr> callExpr = cast<CallExpr>(expr)) {
				if (ShPtr<Variable> var = cast<Variable>(callExpr->getCalledExpr())) {
					// We are finding a local function.
					bool found = false;
					// Searched function.
					ShPtr<Function> func = module->getFuncByName(var->getName());
					if (func) {
						found = true;
					}
					if (ShPtr<IntType> type = cast<IntType>(var->getType())) {
						// Evaluation of statistics and fixing of the type.
						if ((isSigned > isUnsigned) && type->isUnsigned()) {
							changed = true;
							var->setType(IntType::create(type->getSize(), true));
							// If the called expression is a function, we have
							// to change its type, too.
							if (found) {
								func->setRetType(IntType::create(type->getSize(), true));
							}
						} else if ((isSigned <= isUnsigned) && type->isSigned()) {
							changed = true;
							var->setType(IntType::create(type->getSize(), false));
							// If the called expression is a function, we have
							// to change its type, too.
							if (found) {
								func->setRetType(IntType::create(type->getSize(), false));
							}
						}
					}
				}
			}
		}
	}
}

/**
* @brief Checks that types of expressions are correct or not.
*        If not returns cast to correct type.
*
* @param[in] isSigned expected type of integer type of expression.
* @param[in] expr checked expression
*
* * @par Preconditions
*  - @a expr has integer type
*/
ShPtr<Expression> ExprTypesFixer::exprCheckAndChange(bool isSigned,
		ShPtr<Expression> expr) {
	if (ShPtr<IntType> type = cast<IntType>(expr->getType())) {
		// If it is an integer-type variable.
		if (!isSigned && type->isSigned()) {
			// Add cast to unsigned.
			return BitCastExpr::create(expr, IntType::create(
				type->getSize(), false));
		} else if (isSigned && type->isUnsigned()) {
			// Add cast to signed.
			return BitCastExpr::create(expr, IntType::create(
				type->getSize(), true));
		}
	}
	return expr;
}

/**
* @brief Fixes some types to correct type.
*
* @param[in] module Searched module.
*/
void ExprTypesFixer::fixTypes(ShPtr<Module> module) {
	ShPtr<ExprTypesFixer> visitor(new ExprTypesFixer());

	// Sets the probably types (from statistics of Analyser called inside).
	visitor->setProbablyTypes(module);

	// Obtain types from module.
	// Global variables.
	for (auto i = module->global_var_begin(), e = module->global_var_begin();
			i != e; ++i) {
		(*i)->accept(visitor.get());
	}

	// Functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		(*i)->accept(visitor.get());
	}
}

//
// Visits
//

// Casts.
void ExprTypesFixer::visit(ShPtr<ExtCastExpr> expr) {
	// If it is a variable with the int type.
	if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
		expr->setOperand(exprCheckAndChange(true, expr->getOperand()));
	} else if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
		expr->setOperand(exprCheckAndChange(false, expr->getOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<IntToFPCastExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == IntToFPCastExpr::Variant::SIToFP) {
		expr->setOperand(exprCheckAndChange(true, expr->getOperand()));
	} else if (expr->getVariant() == IntToFPCastExpr::Variant::UIToFP) {
		expr->setOperand(exprCheckAndChange(false, expr->getOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<DivOpExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
		// Checking and changing of operands.
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<ModOpExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == ModOpExpr::Variant::SMod) {
		// Checking and changing of operands.
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<AssignStmt> stmt) {
	stmt->getLhs()->accept(this);
	stmt->getRhs()->accept(this);

	ShPtr<Variable> var = cast<Variable>(stmt->getLhs());
	if (!var) {
		return;
	}

	ShPtr<IntType> type = cast<IntType>(var->getType());
	if (!type) {
		return;
	}

	// If right value is expression - division.
	if (ShPtr<DivOpExpr> expr = cast<DivOpExpr>(stmt->getRhs())) {
		// If it is a signed variant of an expression.
		if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
			if (cast<BitCastExpr>(exprCheckAndChange(true, stmt->getLhs()))) {
				stmt->setRhs(BitCastExpr::create(expr, IntType::create(
					type->getSize(), true)));
			}
		// If it is a unsigned variant of an expression.
		} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
			if (cast<BitCastExpr>(exprCheckAndChange(false, stmt->getLhs()))) {
				stmt->setRhs(BitCastExpr::create(expr, IntType::create(
					type->getSize(), false)));
			}
		}
	// If right value is expression - modulation.
	} else if (ShPtr<ModOpExpr> expr = cast<ModOpExpr>(stmt->getRhs())) {
		// If it is a signed variant of an expression.
		if (expr->getVariant() == ModOpExpr::Variant::SMod) {
			if (cast<BitCastExpr>(exprCheckAndChange(true, stmt->getLhs()))) {
				stmt->setRhs(BitCastExpr::create(expr, IntType::create(
					type->getSize(), true)));
			}
		// If it is a unsigned variant of an expression.
		} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
			if (cast<BitCastExpr>(exprCheckAndChange(false, stmt->getLhs()))) {
				stmt->setRhs(BitCastExpr::create(expr, IntType::create(
					type->getSize(), false)));
			}
		}
	// If right value is variable.
	} else {
		// We must check & change right value, because we can't cast left value.
		// Instead "(signed) a = b;" we need a = (unsigned) b;
		if (type->isSigned()) {
			stmt->setRhs(exprCheckAndChange(true, stmt->getRhs()));
		} else {
			stmt->setRhs(exprCheckAndChange(false, stmt->getRhs()));
		}
	}
}

void ExprTypesFixer::visit(ShPtr<VarDefStmt> stmt) {
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		// If right value is expression - division.
		if (ShPtr<DivOpExpr> expr = cast<DivOpExpr>(init)) {
			// If it is a signed variant of an expression.
			if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
				if (cast<BitCastExpr>(exprCheckAndChange(true, stmt->getVar()))) {
					ShPtr<Variable> var = cast<Variable>(stmt->getVar());
					ShPtr<IntType> type = cast<IntType>(var->getType());
					stmt->setInitializer(BitCastExpr::create(init, IntType::create(
						type->getSize(), true)));
				}
			// If it is a unsigned variant of an expression.
			} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
				if (cast<BitCastExpr>(exprCheckAndChange(false, stmt->getVar()))) {
					ShPtr<Variable> var = cast<Variable>(stmt->getVar());
					ShPtr<IntType> type = cast<IntType>(var->getType());
					stmt->setInitializer(BitCastExpr::create(init, IntType::create(
						type->getSize(), false)));
				}
			}
		// If right value is expression - modulation.
		} else if (ShPtr<ModOpExpr> expr = cast<ModOpExpr>(init)) {
			// If it is a signed variant of an expression.
			if (expr->getVariant() == ModOpExpr::Variant::SMod) {
				if (cast<BitCastExpr>(exprCheckAndChange(true, stmt->getVar()))) {
					ShPtr<Variable> var = cast<Variable>(stmt->getVar());
					ShPtr<IntType> type = cast<IntType>(var->getType());
					stmt->setInitializer(BitCastExpr::create(init, IntType::create(
						type->getSize(), true)));
				}
			// If it is a unsigned variant of an expression.
			} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
				if (cast<BitCastExpr>(exprCheckAndChange(false, stmt->getVar()))) {
					ShPtr<Variable> var = cast<Variable>(stmt->getVar());
					ShPtr<IntType> type = cast<IntType>(var->getType());
					stmt->setInitializer(BitCastExpr::create(init, IntType::create(
						type->getSize(), false)));
				}
			}
		// If right value is variable.
		} else if (ShPtr<Variable> var = cast<Variable>(stmt->getVar())) {
			// We must check & change init value, because we can't cast var
			// value. Instead "(signed) a = b;" we need a = (unsigned) b;
			if (ShPtr<IntType> type = cast<IntType>(var->getType())) {
				if (type->isSigned()) {
					stmt->setInitializer(exprCheckAndChange(true, init));
				} else if (type->isUnsigned()) {
					stmt->setInitializer(exprCheckAndChange(false, init));
				}
			}
		}
	}

	OrderedAllVisitor::visit(stmt);
}

void ExprTypesFixer::visit(ShPtr<LtEqOpExpr> expr) {
	// If it is the signed compare operator
	if (expr->getVariant() == LtEqOpExpr::Variant::SCmp) {
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	// If it is the unsigned compare operator
	} else if (expr->getVariant() == LtEqOpExpr::Variant::UCmp) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<GtEqOpExpr> expr) {
	if (expr->getVariant() == GtEqOpExpr::Variant::SCmp) {
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	} else if (expr->getVariant() == GtEqOpExpr::Variant::UCmp) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<LtOpExpr> expr) {
	if (expr->getVariant() == LtOpExpr::Variant::SCmp) {
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	} else if (expr->getVariant() == LtOpExpr::Variant::UCmp) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<GtOpExpr> expr) {
	if (expr->getVariant() == GtOpExpr::Variant::SCmp) {
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(true, expr->getSecondOperand()));
	} else if (expr->getVariant() == GtOpExpr::Variant::UCmp) {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
		expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));
	}

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<BitShlOpExpr> expr) {
	expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));

	OrderedAllVisitor::visit(expr);
}

void ExprTypesFixer::visit(ShPtr<BitShrOpExpr> expr) {
	if (expr->isArithmetical()) {
		expr->setFirstOperand(exprCheckAndChange(true, expr->getFirstOperand()));
	} else {
		expr->setFirstOperand(exprCheckAndChange(false, expr->getFirstOperand()));
	}
	expr->setSecondOperand(exprCheckAndChange(false, expr->getSecondOperand()));

	OrderedAllVisitor::visit(expr);
}

} // namespace llvmir2hll
} // namespace retdec
