/**
* @file include/retdec/llvmir2hll/ir/assign_stmt.h
* @brief An assignment statement.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_ASSIGN_STMT_H
#define RETDEC_LLVMIR2HLL_IR_ASSIGN_STMT_H

#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Variable;
class Visitor;

/**
* @brief An assignment statement.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class AssignStmt final: public Statement {
public:
	static ShPtr<AssignStmt> create(ShPtr<Expression> lhs, ShPtr<Expression> rhs,
		ShPtr<Statement> succ = nullptr);

	virtual ~AssignStmt() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) override;
	virtual ShPtr<Expression> asExpression() const override;

	ShPtr<Expression> getLhs() const;
	ShPtr<Expression> getRhs() const;

	void setLhs(ShPtr<Expression> left);
	void setRhs(ShPtr<Expression> right);

	/// @name Subject Interface
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
	AssignStmt(ShPtr<Expression> lhs, ShPtr<Expression> rhs);

private:
	/// Left-hand side of the assignment.
	ShPtr<Expression> lhs;

	/// Right-hand side of the assignment.
	ShPtr<Expression> rhs;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
