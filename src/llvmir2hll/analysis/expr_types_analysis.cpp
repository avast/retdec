/**
* @file src/llvmir2hll/analysis/expr_types_analysis.cpp
* @brief Implementation of ExprTypesAnalysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/analysis/expr_types_analysis.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
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
#include "retdec/llvmir2hll/ir/unary_op_expr.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new visitor.
*/
ExprTypesAnalysis::ExprTypesAnalysis():
	OrderedAllVisitor() {}

/**
* @brief Destructs the visitor.
*/
ExprTypesAnalysis::~ExprTypesAnalysis() {}

/**
* @brief Adds @a tag to the expression and puts it into @c exprTagsMap.
*
* @param[in] expr Tagged expression.
* @param[in] tag Tag is Signed or Unsigned.
*/
void ExprTypesAnalysis::addTagToExpr(ShPtr<Expression> expr, ExprTag tag) {
	if (isa<IntType>(expr->getType())) {
		// Note: If there is no vector for expr in exprTagsMap, it is created
		//       automatically upon calling exprTagsMap[expr]. Therefore, we do
		//       not have to check its existence prior to pushing the tag.
		exprTagsMap[expr].push_back(tag);
	}
}

/**
* @brief Gets count of found tags of expression @a expr.
*
* @param[in] expr Expression.
* @param[in] tag Counted tag (Signed or Unsigned).
*/
std::size_t ExprTypesAnalysis::getCountOfTag(ShPtr<Expression> expr, ExprTag tag) {
	std::size_t count = 0;
	TagVector &tagsForExpr(exprTagsMap[expr]);
	for (std::size_t i = 0, e = tagsForExpr.size(); i < e; ++i) {
		if (tagsForExpr[i] == tag) {
			count++;
		}
	}
	return count;
}

/**
* @brief Creates a new analysis of integer types.
*/
ShPtr<ExprTypesAnalysis> ExprTypesAnalysis::create() {
	return ShPtr<ExprTypesAnalysis>(new ExprTypesAnalysis());
}

/**
* @brief Fixes some types to correct type.
*
* @param[in] module Searched module.
*/
ExprTypesAnalysis::ExprTagsMap ExprTypesAnalysis::analyzeExprTypes(ShPtr<Module> module) {
	exprTagsMap.clear();
	// Obtain types from module.
	// Global variables.
	for (auto i = module->global_var_begin(), e = module->global_var_begin();
			i != e; ++i) {
		(*i)->accept(this);
	}

	// Functions.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		OrderedAllVisitor::visit(*i);
	}

	return exprTagsMap;
}

//
// Visits
//

// Casts.
void ExprTypesAnalysis::visit(ShPtr<ExtCastExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
		addTagToExpr(expr->getOperand(), ExprTag::Signed);
	} else if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
		addTagToExpr(expr->getOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<IntToFPCastExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == IntToFPCastExpr::Variant::SIToFP) {
		addTagToExpr(expr->getOperand(), ExprTag::Signed);
	} else if (expr->getVariant() == IntToFPCastExpr::Variant::UIToFP) {
		addTagToExpr(expr->getOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<DivOpExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is an unsigned variant of expression.
	} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<ModOpExpr> expr) {
	// If it is a signed variant of an expression.
	if (expr->getVariant() == ModOpExpr::Variant::SMod) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is an unsigned variant of expression.
	} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
		// We can change only the type of a expression.
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		// We can change only the type of a expression.
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<AssignStmt> stmt) {
	// If right value is expression - division.
	if (ShPtr<DivOpExpr> expr = cast<DivOpExpr>(stmt->getRhs())) {
		// If it is a signed variant of an expression.
		if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
			addTagToExpr(stmt->getLhs(), ExprTag::Signed);
		} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
			addTagToExpr(stmt->getLhs(), ExprTag::Unsigned);
		}
	// If right value is expression - modulation.
	} else if (ShPtr<ModOpExpr> expr = cast<ModOpExpr>(stmt->getRhs())) {
		if (expr->getVariant() == ModOpExpr::Variant::SMod) {
			addTagToExpr(stmt->getLhs(), ExprTag::Signed);
		} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
			addTagToExpr(stmt->getLhs(), ExprTag::Unsigned);
		}
	// If right value is signed.
	} if (ShPtr<IntType> type = cast<IntType>(stmt->getRhs()->getType())) {
		if (type->isSigned()) {
			// Now unsigned is maybe signed too, but it is not checked
			// already.
			// We need check it again later.
			addTagToExpr(stmt->getLhs(), ExprTag::Signed);
		}
	}
	// If left expression is signed.
	if (ShPtr<IntType> type = cast<IntType>(stmt->getLhs()->getType())) {
		if (type->isSigned()) {
			// Now unsigned is maybe signed too, but it is not checked
			// already.
			// We need check it again later.
			addTagToExpr(stmt->getRhs(), ExprTag::Signed);
		}
	}
	OrderedAllVisitor::visit(stmt);
}

void ExprTypesAnalysis::visit(ShPtr<VarDefStmt> stmt) {
	lastStmt = stmt;
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		// If right value is expression - division.
		if (ShPtr<DivOpExpr> expr = cast<DivOpExpr>(init)) {
			// If it is signed variant of expression.
			if (expr->getVariant() == DivOpExpr::Variant::SDiv) {
				addTagToExpr(stmt->getVar(), ExprTag::Signed);
			} else if (expr->getVariant() == DivOpExpr::Variant::UDiv) {
				addTagToExpr(stmt->getVar(), ExprTag::Unsigned);
			}
		// If right value is expression - modulation.
		} else if (ShPtr<ModOpExpr> expr = cast<ModOpExpr>(init)) {
			// If it is a signed variant of an expression.
			if (expr->getVariant() == ModOpExpr::Variant::SMod) {
				addTagToExpr(stmt->getVar(), ExprTag::Signed);
			} else if (expr->getVariant() == ModOpExpr::Variant::UMod) {
				addTagToExpr(stmt->getVar(), ExprTag::Unsigned);
			}
		// If init value is signed expression.
		} else if (ShPtr<IntType> type = cast<IntType>(init->getType())) {
			if (type->isSigned()) {
				// Now unsigned is maybe signed too, but it is not checked
				// already.
				// We need check it again later.
				addTagToExpr(stmt->getVar(), ExprTag::Signed);
			}
		}
		// If left value is a signed expression.
		if (ShPtr<IntType> type = cast<IntType>(stmt->getVar()->getType())) {
			if (type->isSigned()) {
				// Now unsigned is maybe signed too, but it is not checked
				// already.
				// We need check it again later.
				addTagToExpr(init, ExprTag::Signed);
			}
		}
	}
	OrderedAllVisitor::visit(stmt);
}

void ExprTypesAnalysis::visit(ShPtr<LtEqOpExpr> expr) {
	// If it is the signed compare operator.
	if (expr->getVariant() == LtEqOpExpr::Variant::SCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is the unsigned compare operator.
	} else if (expr->getVariant() == LtEqOpExpr::Variant::UCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<GtEqOpExpr> expr) {
	// If it is the signed compare operator.
	if (expr->getVariant() == GtEqOpExpr::Variant::SCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is the unsigned compare operator.
	} else if (expr->getVariant() == GtEqOpExpr::Variant::UCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<LtOpExpr> expr) {
	// If it is the signed compare operator.
	if (expr->getVariant() == LtOpExpr::Variant::SCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is the unsigned compare operator.
	} else if (expr->getVariant() == LtOpExpr::Variant::UCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<GtOpExpr> expr) {
	// If it is the signed compare operator.
	if (expr->getVariant() == GtOpExpr::Variant::SCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Signed);
	// If it is the unsigned compare operator.
	} else if (expr->getVariant() == GtOpExpr::Variant::UCmp) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
		addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	}
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<BitShlOpExpr> expr) {
	addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	OrderedAllVisitor::visit(expr);
}

void ExprTypesAnalysis::visit(ShPtr<BitShrOpExpr> expr) {
	if (expr->isArithmetical()) {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Signed);
	} else {
		addTagToExpr(expr->getFirstOperand(), ExprTag::Unsigned);
	}
	addTagToExpr(expr->getSecondOperand(), ExprTag::Unsigned);
	OrderedAllVisitor::visit(expr);
}

} // namespace llvmir2hll
} // namespace retdec
