/**
* @file include/retdec/llvmir2hll/ir/while_loop_stmt.h
* @brief A while loop statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_WHILE_LOOP_STMT_H
#define RETDEC_LLVMIR2HLL_IR_WHILE_LOOP_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A while loop statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class WhileLoopStmt final: public Statement {
public:
	static ShPtr<WhileLoopStmt> create(ShPtr<Expression> cond, ShPtr<Statement> body,
		ShPtr<Statement> succ = nullptr);

	virtual ~WhileLoopStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Expression> getCondition() const;
	ShPtr<Statement> getBody() const;

	void setCondition(ShPtr<Expression> newCond);
	void setBody(ShPtr<Statement> newBody);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject, ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	WhileLoopStmt(ShPtr<Expression> cond, ShPtr<Statement> body);

private:
	/// Loop condition.
	ShPtr<Expression> cond;

	/// Loop body.
	ShPtr<Statement> body;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
