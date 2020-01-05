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
	static WhileLoopStmt* create(Expression* cond, Statement* body,
		Statement* succ = nullptr, Address a = Address::Undefined);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(Expression* oldExpr, Expression* newExpr) override;
	virtual Expression* asExpression() const override;

	Expression* getCondition() const;
	Statement* getBody() const;

	void setCondition(Expression* newCond);
	void setBody(Statement* newBody);

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::WhileLoopStmt; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	WhileLoopStmt(Expression* cond, Statement* body,
		Address a = Address::Undefined);

private:
	/// Loop condition.
	Expression* cond = nullptr;

	/// Loop body.
	Statement* body = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
