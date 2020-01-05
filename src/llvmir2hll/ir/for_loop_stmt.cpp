/**
* @file src/llvmir2hll/ir/for_loop_stmt.cpp
* @brief Implementation of ForLoopStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new for loop statement.
*
* See create() for more information.
*/
ForLoopStmt::ForLoopStmt(Variable* indVar, Expression* startValue,
	Expression* endCond, Expression* step, Statement* body,
	Address a):
		Statement(Value::ValueKind::ForLoopStmt, a), indVar(indVar),
		startValue(startValue), endCond(endCond), step(step), body(body) {}

Value* ForLoopStmt::clone() {
	ForLoopStmt* forLoopStmt(ForLoopStmt::create(
		ucast<Variable>(indVar->clone()),
		ucast<Expression>(startValue->clone()),
		ucast<Expression>(endCond->clone()),
		ucast<Expression>(step->clone()),
		ucast<Statement>(Statement::cloneStatements(body)),
		nullptr,
		getAddress()));
	forLoopStmt->setMetadata(getMetadata());
	return forLoopStmt;
}

bool ForLoopStmt::isEqualTo(Value* otherValue) const {
	// Both types, induction variables, starting values, end conditions, steps,
	// and bodies have to be equal.
	if (ForLoopStmt* otherForLoopStmt = cast<ForLoopStmt>(otherValue)) {
		return indVar->isEqualTo(otherForLoopStmt->indVar) &&
			startValue->isEqualTo(otherForLoopStmt->startValue) &&
			endCond->isEqualTo(otherForLoopStmt->endCond) &&
			step->isEqualTo(otherForLoopStmt->step) &&
			body->isEqualTo(otherForLoopStmt->body);
	}
	return false;
}

void ForLoopStmt::replace(Expression* oldExpr, Expression* newExpr) {
	if (oldExpr == indVar) {
		Variable* newIndVar(cast<Variable>(newExpr));
		ASSERT_MSG(newIndVar,
			"induction variable can be replaced only with a variable");
		setIndVar(newIndVar);
	} else {
		indVar->replace(oldExpr, newExpr);
	}

	if (oldExpr == startValue) {
		setStartValue(newExpr);
	} else {
		startValue->replace(oldExpr, newExpr);
	}

	if (oldExpr == endCond) {
		setEndCond(newExpr);
	} else {
		endCond->replace(oldExpr, newExpr);
	}

	if (oldExpr == step) {
		setStep(newExpr);
	} else {
		step->replace(oldExpr, newExpr);
	}
}

Expression* ForLoopStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the induction variable.
*/
Variable* ForLoopStmt::getIndVar() const {
	return indVar;
}

/**
* @brief Returns the starting value.
*/
Expression* ForLoopStmt::getStartValue() const {
	return startValue;
}

/**
* @brief Returns the end condition.
*/
Expression* ForLoopStmt::getEndCond() const {
	return endCond;
}

/**
* @brief Returns the step.
*/
Expression* ForLoopStmt::getStep() const {
	return step;
}

/**
* @brief Returns the body.
*/
Statement* ForLoopStmt::getBody() const {
	return body;
}

/**
* @brief Sets a new induction variable.
*
* @par Preconditions
*  - @a newIndVar is non-null
*/
void ForLoopStmt::setIndVar(Variable* newIndVar) {
	PRECONDITION_NON_NULL(newIndVar);

	indVar->removeObserver(this);
	newIndVar->addObserver(this);
	indVar = newIndVar;
}

/**
* @brief Sets a new start value.
*
* @par Preconditions
*  - @a newStartValue is non-null
*/
void ForLoopStmt::setStartValue(Expression* newStartValue) {
	PRECONDITION_NON_NULL(newStartValue);

	startValue->removeObserver(this);
	newStartValue->addObserver(this);
	startValue = newStartValue;
}

/**
* @brief Sets a new end condition.
*
* @par Preconditions
*  - @a newEndCond is non-null
*/
void ForLoopStmt::setEndCond(Expression* newEndCond) {
	PRECONDITION_NON_NULL(newEndCond);

	endCond->removeObserver(this);
	newEndCond->addObserver(this);
	endCond = newEndCond;
}

/**
* @brief Sets a new step.
*
* @par Preconditions
*  - @a newStep is non-null
*/
void ForLoopStmt::setStep(Expression* newStep) {
	PRECONDITION_NON_NULL(newStep);

	step->removeObserver(this);
	newStep->addObserver(this);
	step = newStep;
}

/**
* @brief Sets a new body.
*
* @par Preconditions
*  - @a newBody is non-null
*/
void ForLoopStmt::setBody(Statement* newBody) {
	PRECONDITION_NON_NULL(newBody);

	body->removeObserver(this);
	newBody->addObserver(this);
	body = newBody;
}

/**
* @brief Constructs a new for loop statement.
*
* @param[in] indVar Induction variable.
* @param[in] startValue Starting value.
* @param[in] endCond End condition.
* @param[in] step Step.
* @param[in] body Body.
* @param[in] succ Follower of the statement in the program flow.
* @param[in] a Address.
*
* The loop is of the following form (written in C):
* @code
* for (indVar = startValue; endCond; indVar += step)
*     body
* @endcode
*
* @par Preconditions
*  - all operands except @a succ are non-null
*/
ForLoopStmt* ForLoopStmt::create(Variable* indVar,
		Expression* startValue, Expression* endCond,
		Expression* step, Statement* body, Statement* succ,
		Address a) {
	PRECONDITION_NON_NULL(indVar);
	PRECONDITION_NON_NULL(startValue);
	PRECONDITION_NON_NULL(endCond);
	PRECONDITION_NON_NULL(step);
	PRECONDITION_NON_NULL(body);

	ForLoopStmt* stmt(new ForLoopStmt(indVar, startValue, endCond,
		step, body, a));
	stmt->setSuccessor(succ);

	// Initialization (recall that this cannot be called in a
	// constructor).
	indVar->addObserver(stmt);
	startValue->addObserver(stmt);
	endCond->addObserver(stmt);
	step->addObserver(stmt);
	body->addObserver(stmt);

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is the induction
* variable, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of the statement
*  - @a arg is not a statement/variable/expression
*
* @par Preconditions
*  - @a subject is non-null
*
* @see Subject::update()
*/
void ForLoopStmt::update(Value* subject, Value* arg) {
	PRECONDITION_NON_NULL(subject);

	Statement* newBody = cast<Statement>(arg);
	if (subject == body && newBody) {
		setBody(newBody);
		return;
	}

	Variable* newIndVar = cast<Variable>(arg);
	if (subject == indVar && newIndVar) {
		setIndVar(newIndVar);
		return;
	}

	Expression* newExpr = cast<Expression>(arg);
	if (!newExpr) {
		return;
	}

	if (subject == startValue) {
		setStartValue(newExpr);
	} else if (subject == endCond) {
		setEndCond(newExpr);
	} else if (subject == step) {
		setStep(newExpr);
	}
}

void ForLoopStmt::accept(Visitor *v) {
	v->visit(ucast<ForLoopStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
