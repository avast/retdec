/**
* @file include/retdec/llvmir2hll/hll/compound_op_managers/py_compound_op_manager.h
* @brief A compound operator manager for the Python' language.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGERS_PY_COMPOUND_OP_MANAGER_H
#define RETDEC_LLVMIR2HLL_HLL_COMPOUND_OP_MANAGERS_PY_COMPOUND_OP_MANAGER_H

#include "retdec/llvmir2hll/hll/compound_op_manager.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Compound operator manager for the Python' language.
*
* This is a concrete compound operator manager which should not be subclassed.
*/
class PyCompoundOpManager final: public CompoundOpManager {
public:
	PyCompoundOpManager();

	virtual ~PyCompoundOpManager() override;

	virtual std::string getId() const override;

private:
	virtual void optimizeToCompoundOp(ShPtr<AddOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<SubOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<MulOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<ModOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<DivOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<BitAndOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<BitOrOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<BitXorOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<BitShlOpExpr> expr,
		ShPtr<Expression> operand) override;
	virtual void optimizeToCompoundOp(ShPtr<BitShrOpExpr> expr,
		ShPtr<Expression> operand) override;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
