/**
* @file include/retdec/llvmir2hll/ir/for_loop_stmt.h
* @brief A for loop statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FOR_LOOP_STMT_H
#define RETDEC_LLVMIR2HLL_IR_FOR_LOOP_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Variable;
class Visitor;

/**
* @brief A for loop statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ForLoopStmt final: public Statement {
public:
	static ForLoopStmt* create(Variable* indVar, Expression* startValue,
		Expression* endCond, Expression* step,
		Statement* body, Statement* succ = nullptr,
		Address a = Address::Undefined);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(Expression* oldExpr, Expression* newExpr) override;
	virtual Expression* asExpression() const override;

	Variable* getIndVar() const;
	Expression* getStartValue() const;
	Expression* getEndCond() const;
	Expression* getStep() const;
	Statement* getBody() const;

	void setIndVar(Variable* newIndVar);
	void setStartValue(Expression* newStartValue);
	void setEndCond(Expression* newEndCond);
	void setStep(Expression* newStep);
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
        return v->getKind() == Value::ValueKind::ForLoopStmt; }

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ForLoopStmt(Variable* indVar, Expression* startValue,
		Expression* endCond, Expression* step,
		Statement* body, Address a);

private:
	/// Induction variable.
	Variable* indVar = nullptr;

	/// Starting value.
	Expression* startValue = nullptr;

	/// End condition.
	Expression* endCond = nullptr;

	/// Step.
	Expression* step = nullptr;

	/// Body.
	Statement* body = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
