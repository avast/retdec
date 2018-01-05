/**
* @file src/llvmir2hll/hll/compound_op_managers/py_compound_op_manager.cpp
* @brief Implementation of PyCompoundOpManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_managers/py_compound_op_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new Python' compound operator manager.
*/
PyCompoundOpManager::PyCompoundOpManager(): CompoundOpManager() {}

/**
* @brief Destructor.
*/
PyCompoundOpManager::~PyCompoundOpManager() {}

std::string PyCompoundOpManager::getId() const {
	return "PyCompoundOpManager";
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<AddOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("+=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<SubOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("-=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<MulOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("*=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<DivOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("/=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<ModOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("%=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<BitShlOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("<<=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<BitShrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp(">>=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<BitAndOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("&=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<BitOrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("|=", operand);
}

void PyCompoundOpManager::optimizeToCompoundOp(ShPtr<BitXorOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("^=", operand);
}

} // namespace llvmir2hll
} // namespace retdec
