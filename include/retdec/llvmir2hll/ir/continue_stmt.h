/**
* @file include/retdec/llvmir2hll/ir/continue_stmt.h
* @brief A continue statement to continue looping.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONTINUE_STMT_H
#define RETDEC_LLVMIR2HLL_IR_CONTINUE_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A continue statement to continue looping.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ContinueStmt final: public Statement {
public:
	static ShPtr<ContinueStmt> create();

	virtual ~ContinueStmt() override;

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
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ContinueStmt();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
