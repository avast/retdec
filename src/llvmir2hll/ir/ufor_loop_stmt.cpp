/**
* @file src/llvmir2hll/ir/ufor_loop_stmt.cpp
* @brief Implementation of UForLoopStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new universal for loop statement.
*
* See create() for more information.
*/
UForLoopStmt::UForLoopStmt(
		ShPtr<Expression> init,
		ShPtr<Expression> cond,
		ShPtr<Expression> step,
		ShPtr<Statement> body):
	init(init), initIsDefinition(false), cond(cond), step(step),
	body(body) {}

/**
* @brief Destructs the statement.
*/
UForLoopStmt::~UForLoopStmt() = default;

ShPtr<Value> UForLoopStmt::clone() {
	auto loop = UForLoopStmt::create(
		ucast<Expression>(init->clone()),
		ucast<Expression>(cond->clone()),
		ucast<Expression>(step->clone()),
		ucast<Statement>(body->clone())
	);
	loop->setMetadata(getMetadata());
	return loop;
}

bool UForLoopStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// Types, parts, and bodies have to be equal.
	if (auto otherLoop = cast<UForLoopStmt>(otherValue)) {
		return init->isEqualTo(otherLoop->init) &&
			cond->isEqualTo(otherLoop->cond) &&
			step->isEqualTo(otherLoop->step) &&
			body->isEqualTo(otherLoop->body);
	}
	return false;
}

void UForLoopStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	if (oldExpr == init) {
		setInit(newExpr);
	} else if (init) {
		init->replace(oldExpr, newExpr);
	}

	if (oldExpr == cond) {
		setCond(cond);
	} else if (cond) {
		cond->replace(oldExpr, newExpr);
	}

	if (oldExpr == step) {
		setStep(newExpr);
	} else if (step) {
		step->replace(oldExpr, newExpr);
	}
}

ShPtr<Expression> UForLoopStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the initialization part.
*/
ShPtr<Expression> UForLoopStmt::getInit() const {
	return init;
}

/**
* @brief Returns the conditional part.
*/
ShPtr<Expression> UForLoopStmt::getCond() const {
	return cond;
}

/**
* @brief Returns the step part.
*/
ShPtr<Expression> UForLoopStmt::getStep() const {
	return step;
}

/**
* @brief Returns the body.
*/
ShPtr<Statement> UForLoopStmt::getBody() const {
	return body;
}

/**
* @brief Sets a new initialization part.
*
* @par Preconditions
*  - @a newInit is non-null
*/
void UForLoopStmt::setInit(ShPtr<Expression> newInit) {
	PRECONDITION_NON_NULL(newInit);

	init->removeObserver(shared_from_this());
	newInit->addObserver(shared_from_this());
	init = newInit;
}

/**
* @brief Sets a new conditional part.
*
* @par Preconditions
*  - @a newCond is non-null
*/
void UForLoopStmt::setCond(ShPtr<Expression> newCond) {
	PRECONDITION_NON_NULL(newCond);

	cond->removeObserver(shared_from_this());
	newCond->addObserver(shared_from_this());
	cond = newCond;
}

/**
* @brief Sets a new step part.
*
* @par Preconditions
*  - @a newStep is non-null
*/
void UForLoopStmt::setStep(ShPtr<Expression> newStep) {
	PRECONDITION_NON_NULL(newStep);

	step->removeObserver(shared_from_this());
	newStep->addObserver(shared_from_this());
	step = newStep;
}

/**
* @brief Sets a new body.
*
* @par Preconditions
*  - @a newBody is non-null
*/
void UForLoopStmt::setBody(ShPtr<Statement> newBody) {
	PRECONDITION_NON_NULL(newBody);

	body->removeObserver(shared_from_this());
	newBody->addObserver(shared_from_this());
	body = newBody;
}

/**
* @brief Is the initialization part a definition of a variable?
*/
bool UForLoopStmt::isInitDefinition() const {
	return initIsDefinition;
}

/**
* @brief Marks the initialization part of the statement as a definition of the
*        variable assigned in the part.
*/
void UForLoopStmt::markInitAsDefinition() {
	initIsDefinition = true;
}

/**
* @brief Constructs a new universal for loop statement.
*
* @param[in] init Initialization part.
* @param[in] cond Conditional part.
* @param[in] step Step part (eg. increment/decrement).
* @param[in] body Body.
* @param[in] succ Follower of the statement in the program flow (optional).
*
* @par Preconditions
*  - body is non-null
*/
ShPtr<UForLoopStmt> UForLoopStmt::create(
		ShPtr<Expression> init,
		ShPtr<Expression> cond,
		ShPtr<Expression> step,
		ShPtr<Statement> body,
		ShPtr<Statement> succ) {
	PRECONDITION_NON_NULL(body);

	ShPtr<UForLoopStmt> stmt(new UForLoopStmt(init, cond, step, body));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	if (init) {
		init->addObserver(stmt);
	}
	if (cond) {
		cond->addObserver(stmt);
	}
	if (step) {
		step->addObserver(stmt);
	}
	body->addObserver(stmt);

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is an expression
* in one of the parts, this function replaces it with @a arg.
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
void UForLoopStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	auto newBody = cast<Statement>(arg);
	if (subject == body && newBody) {
		setBody(newBody);
		return;
	}

	auto newExpr = cast<Expression>(arg);
	if (!newExpr) {
		return;
	}

	if (subject == init) {
		setInit(newExpr);
	} else if (subject == cond) {
		setCond(newExpr);
	} else if (subject == step) {
		setStep(newExpr);
	}
}

void UForLoopStmt::accept(Visitor *v) {
	v->visit(ucast<UForLoopStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
