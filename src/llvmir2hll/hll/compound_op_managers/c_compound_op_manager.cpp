/**
* @file src/llvmir2hll/hll/compound_op_managers/c_compound_op_manager.cpp
* @brief Implementation of CCompoundOpManager.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/hll/compound_op_managers/c_compound_op_manager.h"
#include "retdec/llvmir2hll/ir/const_int.h"

namespace retdec {
namespace llvmir2hll {

namespace {

/**
* @brief Returns @c true if the given operand is a constant integer with
*        value @c 1, @c false otherwise.
*/
bool isConstIntOne(ShPtr<Expression> operand) {
	ShPtr<ConstInt> constInt(cast<ConstInt>(operand));
	return constInt && constInt->isOne();
}

} // anonymous namespace

/**
* @brief Constructs a new C compound operator manager.
*/
CCompoundOpManager::CCompoundOpManager(): CompoundOpManager() {}

/**
* @brief Destructor.
*/
CCompoundOpManager::~CCompoundOpManager() {}

std::string CCompoundOpManager::getId() const {
	return "CCompoundOpManager";
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<AddOpExpr> expr,
		ShPtr<Expression> operand) {
	if (isConstIntOne(operand)) {
		createResultingUnaryCompoundOp("++");
	} else {
		createResultingBinaryCompoundOp("+=", operand);
	}
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<SubOpExpr> expr,
		ShPtr<Expression> operand) {
	if (isConstIntOne(operand)) {
		createResultingUnaryCompoundOp("--");
	} else {
		createResultingBinaryCompoundOp("-=", operand);
	}
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<MulOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("*=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<DivOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("/=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<ModOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("%=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<BitShlOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("<<=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<BitShrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp(">>=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<BitAndOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("&=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<BitOrOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("|=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ShPtr<BitXorOpExpr> expr,
		ShPtr<Expression> operand) {
	createResultingBinaryCompoundOp("^=", operand);
}

} // namespace llvmir2hll
} // namespace retdec
