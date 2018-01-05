/**
* @file src/llvmir2hll/ir/while_loop_stmt.cpp
* @brief Implementation of WhileLoopStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new while loop statement.
*
* See create() for more information.
*/
WhileLoopStmt::WhileLoopStmt(ShPtr<Expression> cond, ShPtr<Statement> body):
	cond(cond), body(body) {}

/**
* @brief Destructs the statement.
*/
WhileLoopStmt::~WhileLoopStmt() {}

ShPtr<Value> WhileLoopStmt::clone() {
	ShPtr<WhileLoopStmt> whileLoopStmt(WhileLoopStmt::create(
		ucast<Expression>(cond->clone()), ucast<Statement>(body->clone())));
	whileLoopStmt->setMetadata(getMetadata());
	return whileLoopStmt;
}

bool WhileLoopStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types, loop conditions, and bodies have to be equal.
	if (ShPtr<WhileLoopStmt> otherWhileLoopStmt = cast<WhileLoopStmt>(otherValue)) {
		return cond->isEqualTo(otherWhileLoopStmt->cond) &&
			body->isEqualTo(otherWhileLoopStmt->body);

	}
	return false;
}

void WhileLoopStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	if (oldExpr == cond) {
		setCondition(newExpr);
	} else {
		cond->replace(oldExpr, newExpr);
	}
}

ShPtr<Expression> WhileLoopStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the loop condition.
*/
ShPtr<Expression> WhileLoopStmt::getCondition() const {
	return cond;
}

/**
* @brief Returns the loop body.
*/
ShPtr<Statement> WhileLoopStmt::getBody() const {
	return body;
}

/**
* @brief Sets a condition
*
* @par Preconditions
*  - @a newCond is non-null
*/
void WhileLoopStmt::setCondition(ShPtr<Expression> newCond) {
	PRECONDITION_NON_NULL(newCond);

	cond->removeObserver(shared_from_this());
	newCond->addObserver(shared_from_this());
	cond = newCond;
}

/**
* @brief Sets a new body.
*
* @par Preconditions
*  - @a newBody is non-null
*/
void WhileLoopStmt::setBody(ShPtr<Statement> newBody) {
	PRECONDITION_NON_NULL(newBody);

	body->removeObserver(shared_from_this());
	newBody->addObserver(shared_from_this());
	newBody->removePredecessors(true);
	body = newBody;
}

/**
* @brief Constructs a new while loop statement.
*
* @param[in] cond Loop condition.
* @param[in] body Loop body.
* @param[in] succ Follower of the statement in the program flow.
*
* An equivalent to the while loop in C, i.e. <tt>while (cond) body</tt>.
*
* @par Preconditions
*  - @a cond and @a body are non-null
*/
ShPtr<WhileLoopStmt> WhileLoopStmt::create(ShPtr<Expression> cond, ShPtr<Statement> body,
		ShPtr<Statement> succ) {
	PRECONDITION_NON_NULL(cond);
	PRECONDITION_NON_NULL(body);

	ShPtr<WhileLoopStmt> stmt(new WhileLoopStmt(cond, body));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	cond->addObserver(stmt);
	body->addObserver(stmt);
	body->removePredecessors(true);

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @arg. For example, if @a subject is the condition,
* this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of the statement
*  - @a arg is not a statement/expression
*
* @par Preconditions
*  - @a subject is non-null
*
* @see Subject::update()
*/
void WhileLoopStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	ShPtr<Statement> newBody = cast<Statement>(arg);
	if (subject == body && newBody) {
		setBody(newBody);
		return;
	}

	ShPtr<Expression> newCond = cast<Expression>(arg);
	if (subject == cond && newCond) {
		setCondition(newCond);
	}
}

void WhileLoopStmt::accept(Visitor *v) {
	v->visit(ucast<WhileLoopStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
