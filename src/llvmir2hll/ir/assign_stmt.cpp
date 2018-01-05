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
AssignStmt::AssignStmt(ShPtr<Expression> lhs, ShPtr<Expression> rhs):
	lhs(lhs), rhs(rhs) {}

/**
* @brief Destructs the statement.
*/
AssignStmt::~AssignStmt() {}

ShPtr<Value> AssignStmt::clone() {
	ShPtr<AssignStmt> assignStmt(AssignStmt::create(
		ucast<Expression>(lhs->clone()), ucast<Expression>(rhs->clone())));
	assignStmt->setMetadata(getMetadata());
	return assignStmt;
}

bool AssignStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and values of all operands have to be equal.
	if (ShPtr<AssignStmt> otherAssignStmt = cast<AssignStmt>(otherValue)) {
		return lhs->isEqualTo(otherAssignStmt->lhs) &&
			rhs->isEqualTo(otherAssignStmt->rhs);
	}
	return false;
}

void AssignStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
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

ShPtr<Expression> AssignStmt::asExpression() const {
	return AssignOpExpr::create(lhs, rhs);
}

/**
* @brief Returns the left-hand side of the assignment.
*/
ShPtr<Expression> AssignStmt::getLhs() const {
	return lhs;
}

/**
* @brief Returns the left-hand side of the assignment.
*/
ShPtr<Expression> AssignStmt::getRhs() const {
	return rhs;
}

/**
* @brief Set the left-hand side of the assignment.
*
* @par Preconditions
*  - @a left is non-null
*/
void AssignStmt::setLhs(ShPtr<Expression> left) {
	PRECONDITION_NON_NULL(left);

	lhs->removeObserver(shared_from_this());
	left->addObserver(shared_from_this());
	lhs = left;
}

/**
* @brief Set the right-hand side of the assignment.
*
* @par Preconditions
*  - @a right is non-null
*/
void AssignStmt::setRhs(ShPtr<Expression> right) {
	PRECONDITION_NON_NULL(right);

	rhs->removeObserver(shared_from_this());
	right->addObserver(shared_from_this());
	rhs = right;
}

/**
* @brief Creates a new assignment statement.
*
* @param[in] lhs Left-hand side of the assignment.
* @param[in] rhs Right-hand side of the assignment.
* @param[in] succ Follower of the statement in the program flow.
*
* @par Preconditions
*  - @a lhs and @a rhs are non-null
*/
ShPtr<AssignStmt> AssignStmt::create(ShPtr<Expression> lhs, ShPtr<Expression> rhs,
			ShPtr<Statement> succ) {
	PRECONDITION_NON_NULL(lhs);
	PRECONDITION_NON_NULL(rhs);

	ShPtr<AssignStmt> stmt(new AssignStmt(lhs, rhs));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
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
void AssignStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newExpr = cast<Expression>(arg);
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
	v->visit(ucast<AssignStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
