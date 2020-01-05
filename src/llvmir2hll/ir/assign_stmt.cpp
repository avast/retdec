/**
* @file src/llvmir2hll/ir/assign_stmt.cpp
* @brief Implementation of AssignStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new assignment statement.
*
* See create() for more information.
*/
AssignStmt::AssignStmt(Expression* lhs, Expression* rhs, Address a):
	Statement(a), lhs(lhs), rhs(rhs) {}

Value* AssignStmt::clone() {
	AssignStmt* assignStmt(AssignStmt::create(
		ucast<Expression>(lhs->clone()), ucast<Expression>(rhs->clone()),
		nullptr, getAddress()));
	assignStmt->setMetadata(getMetadata());
	return assignStmt;
}

bool AssignStmt::isEqualTo(Value* otherValue) const {
	// Both types and values of all operands have to be equal.
	if (AssignStmt* otherAssignStmt = cast<AssignStmt>(otherValue)) {
		return lhs->isEqualTo(otherAssignStmt->lhs) &&
			rhs->isEqualTo(otherAssignStmt->rhs);
	}
	return false;
}

void AssignStmt::replace(Expression* oldExpr, Expression* newExpr) {
	if (oldExpr == lhs) {
		setLhs(newExpr);
	} else {
		lhs->replace(oldExpr, newExpr);
	}

	if (oldExpr == rhs) {
		setRhs(newExpr);
	} else {
		rhs->replace(oldExpr, newExpr);
	}
}

Expression* AssignStmt::asExpression() const {
	return AssignOpExpr::create(lhs, rhs);
}

/**
* @brief Returns the left-hand side of the assignment.
*/
Expression* AssignStmt::getLhs() const {
	return lhs;
}

/**
* @brief Returns the left-hand side of the assignment.
*/
Expression* AssignStmt::getRhs() const {
	return rhs;
}

/**
* @brief Set the left-hand side of the assignment.
*
* @par Preconditions
*  - @a left is non-null
*/
void AssignStmt::setLhs(Expression* left) {
	PRECONDITION_NON_NULL(left);

	lhs->removeObserver(this);
	left->addObserver(this);
	lhs = left;
}

/**
* @brief Set the right-hand side of the assignment.
*
* @par Preconditions
*  - @a right is non-null
*/
void AssignStmt::setRhs(Expression* right) {
	PRECONDITION_NON_NULL(right);

	rhs->removeObserver(this);
	right->addObserver(this);
	rhs = right;
}

/**
* @brief Creates a new assignment statement.
*
* @param[in] lhs Left-hand side of the assignment.
* @param[in] rhs Right-hand side of the assignment.
* @param[in] succ Follower of the statement in the program flow.
* @param[in] a Address.
*
* @par Preconditions
*  - @a lhs and @a rhs are non-null
*/
AssignStmt* AssignStmt::create(Expression* lhs, Expression* rhs,
			Statement* succ, Address a) {
	PRECONDITION_NON_NULL(lhs);
	PRECONDITION_NON_NULL(rhs);

	AssignStmt* stmt(new AssignStmt(lhs, rhs, a));
	stmt->setSuccessor(succ);

	// Initialization (recall that this cannot be called in a
	// constructor).
	lhs->addObserver(stmt);
	rhs->addObserver(stmt);

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is the left-hand
* side of this statement, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to the left-hand side nor to the right-hand
*    side of this statement
*  - @a arg is not an expression
*
* @par Preconditions
*  - both arguments are non-null
*
* @see Subject::update()
*/
void AssignStmt::update(Value* subject, Value* arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	Expression* newExpr = cast<Expression>(arg);
	if (!newExpr) {
		return;
	}

	if (subject == lhs) {
		setLhs(newExpr);
	} else if (subject == rhs) {
		setRhs(newExpr);
	}
}

void AssignStmt::accept(Visitor *v) {
	v->visit(ucast<AssignStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
