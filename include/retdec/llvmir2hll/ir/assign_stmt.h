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
	static AssignStmt* create(Expression* lhs, Expression* rhs,
		Statement* succ = nullptr, Address a = Address::Undefined);

	virtual Value* clone() override;
	virtual bool isEqualTo(Value* otherValue) const override;
	virtual bool isCompound() override { return false; }
	virtual void replace(Expression* oldExpr, Expression* newExpr) override;
	virtual Expression* asExpression() const override;

	Expression* getLhs() const;
	Expression* getRhs() const;

	void setLhs(Expression* left);
	void setRhs(Expression* right);

	/// @name Subject Interface
	/// @{
	virtual void update(Value* subject, Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	AssignStmt(Expression* lhs, Expression* rhs,
		Address a = Address::Undefined);

private:
	/// Left-hand side of the assignment.
	Expression* lhs = nullptr;

	/// Right-hand side of the assignment.
	Expression* rhs = nullptr;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
