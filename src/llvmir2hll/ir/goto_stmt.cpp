/**
* @file src/llvmir2hll/ir/goto_stmt.cpp
* @brief Implementation of GotoStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new goto statement.
*
* See create() for more information.
*/
GotoStmt::GotoStmt(ShPtr<Statement> target): target(target) {}

/**
* @brief Destructs the statement.
*/
GotoStmt::~GotoStmt() {}

ShPtr<Value> GotoStmt::clone() {
	ShPtr<GotoStmt> gotoStmt(GotoStmt::create(target));
	gotoStmt->setMetadata(getMetadata());
	return gotoStmt;
}

bool GotoStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and targets have to be equal.
	if (ShPtr<GotoStmt> otherGotoStmt = cast<GotoStmt>(otherValue)) {
		return target->isEqualTo(otherGotoStmt->target);
	}
	return false;
}

void GotoStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	// There is nothing to do.
}

ShPtr<Expression> GotoStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the target of the goto statement.
*/
ShPtr<Statement> GotoStmt::getTarget() const {
	return target;
}

/**
* @brief Sets a new target.
*
* @par Preconditions
*  - @a newTarget is non-null
*/
void GotoStmt::setTarget(ShPtr<Statement> newTarget) {
	PRECONDITION_NON_NULL(newTarget);

	target->removeObserver(shared_from_this());
	target->removePredecessor(ucast<Statement>(shared_from_this()));
	newTarget->addObserver(shared_from_this());
	newTarget->addPredecessor(ucast<Statement>(shared_from_this()));
	target = newTarget;
}

/**
* @brief Creates a new goto statement.
*
* @param[in] target Jump target.
*
* @par Preconditions
*  - @a target is non-null
*/
ShPtr<GotoStmt> GotoStmt::create(ShPtr<Statement> target) {
	PRECONDITION_NON_NULL(target);

	ShPtr<GotoStmt> gotoStmt(new GotoStmt(target));

	// Initialization (recall that shared_from_this(), which is called in
	// setTarget(), cannot be called in a constructor).
	target->addObserver(gotoStmt);
	target->addPredecessor(gotoStmt);

	return gotoStmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* If @a subject is the jump target of this statement, this function replaces it
* with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to the jump target
*  - @a arg is not a statement
*
* @par Preconditions
*  - both @a subject and @a arg are non-null
*
* @see Subject::update()
*/
void GotoStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Statement> newTarget = cast<Statement>(arg);
	if (arg && !newTarget) {
		return;
	}

	if (subject == target) {
		setTarget(newTarget);
	}
}

void GotoStmt::accept(Visitor *v) {
	v->visit(ucast<GotoStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
