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
bool isConstIntOne(Expression* operand) {
	ConstInt* constInt(cast<ConstInt>(operand));
	return constInt && constInt->isOne();
}

} // anonymous namespace

/**
* @brief Constructs a new C compound operator manager.
*/
CCompoundOpManager::CCompoundOpManager(): CompoundOpManager() {}

std::string CCompoundOpManager::getId() const {
	return "CCompoundOpManager";
}

void CCompoundOpManager::optimizeToCompoundOp(AddOpExpr* expr,
		Expression* operand) {
	if (isConstIntOne(operand)) {
		createResultingUnaryCompoundOp("++");
	} else {
		createResultingBinaryCompoundOp("+=", operand);
	}
}

void CCompoundOpManager::optimizeToCompoundOp(SubOpExpr* expr,
		Expression* operand) {
	if (isConstIntOne(operand)) {
		createResultingUnaryCompoundOp("--");
	} else {
		createResultingBinaryCompoundOp("-=", operand);
	}
}

void CCompoundOpManager::optimizeToCompoundOp(MulOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("*=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(DivOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("/=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(ModOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("%=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(BitShlOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("<<=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(BitShrOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp(">>=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(BitAndOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("&=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(BitOrOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("|=", operand);
}

void CCompoundOpManager::optimizeToCompoundOp(BitXorOpExpr* expr,
		Expression* operand) {
	createResultingBinaryCompoundOp("^=", operand);
}

} // namespace llvmir2hll
} // namespace retdec
