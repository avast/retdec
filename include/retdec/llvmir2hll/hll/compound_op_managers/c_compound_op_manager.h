/**
* @file include/retdec/llvmir2hll/hll/compound_op_managers/c_compound_op_manager.h
* @brief A compound operator manager for the C language.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGERS_C_COMPOUND_OP_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGERS_C_COMPOUND_OP_MANAGER_H

#include "retdec/llvmir2hll/hll/compound_op_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Compound operator manager for the C language.
*
* This is a concrete compound operator manager which should not be subclassed.
*/
class CCompoundOpManager final: public CompoundOpManager {
public:
	CCompoundOpManager();

	virtual std::string getId() const override;

private:
	virtual void optimizeToCompoundOp(AddOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(SubOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(MulOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(ModOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(DivOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(BitAndOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(BitOrOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(BitXorOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(BitShlOpExpr* expr,
		Expression* operand) override;
	virtual void optimizeToCompoundOp(BitShrOpExpr* expr,
		Expression* operand) override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
