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
	static ShPtr<ForLoopStmt> create(ShPtr<Variable> indVar, ShPtr<Expression> startValue,
		ShPtr<Expression> endCond, ShPtr<Expression> step,
		ShPtr<Statement> body, ShPtr<Statement> succ = nullptr);

	virtual ~ForLoopStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return true; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Variable> getIndVar() const;
	ShPtr<Expression> getStartValue() const;
	ShPtr<Expression> getEndCond() const;
	ShPtr<Expression> getStep() const;
	ShPtr<Statement> getBody() const;

	void setIndVar(ShPtr<Variable> newIndVar);
	void setStartValue(ShPtr<Expression> newStartValue);
	void setEndCond(ShPtr<Expression> newEndCond);
	void setStep(ShPtr<Expression> newStep);
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
	ForLoopStmt(ShPtr<Variable> indVar, ShPtr<Expression> startValue,
		ShPtr<Expression> endCond, ShPtr<Expression> step,
		ShPtr<Statement> body);

private:
	/// Induction variable.
	ShPtr<Variable> indVar;

	/// Starting value.
	ShPtr<Expression> startValue;

	/// End condition.
	ShPtr<Expression> endCond;

	/// Step.
	ShPtr<Expression> step;

	/// Body.
	ShPtr<Statement> body;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
