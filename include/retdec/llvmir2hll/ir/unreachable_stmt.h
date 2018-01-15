/**
* @file include/retdec/llvmir2hll/ir/unreachable_stmt.h
* @brief An unreachable statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_UNREACHABLE_STMT_H
#define RETDEC_LLVMIR2HLL_IR_UNREACHABLE_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief An unreachable statement.
*
* Instances of this class have reference object semantics.
*/
class UnreachableStmt: public Statement {
public:
	static ShPtr<UnreachableStmt> create();

	virtual ~UnreachableStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	UnreachableStmt();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
