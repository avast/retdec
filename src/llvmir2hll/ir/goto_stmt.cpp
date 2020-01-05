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
GotoStmt::GotoStmt(Statement* target, Address a):
	Statement(a), target(target) {}

Value* GotoStmt::clone() {
	GotoStmt* gotoStmt(GotoStmt::create(target, getAddress()));
	gotoStmt->setMetadata(getMetadata());
	return gotoStmt;
}

bool GotoStmt::isEqualTo(Value* otherValue) const {
	// Both types and targets have to be equal.
	if (GotoStmt* otherGotoStmt = cast<GotoStmt>(otherValue)) {
		return target->isEqualTo(otherGotoStmt->target);
	}
	return false;
}

void GotoStmt::replace(Expression* oldExpr, Expression* newExpr) {
	// There is nothing to do.
}

Expression* GotoStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the target of the goto statement.
*/
Statement* GotoStmt::getTarget() const {
	return target;
}

/**
* @brief Sets a new target.
*
* @par Preconditions
*  - @a newTarget is non-null
*/
void GotoStmt::setTarget(Statement* newTarget) {
	PRECONDITION_NON_NULL(newTarget);

	target->removeObserver(this);
	target->removePredecessor(ucast<Statement>(this));
	newTarget->addObserver(this);
	newTarget->addPredecessor(ucast<Statement>(this));
	target = newTarget;
}

/**
* @brief Creates a new goto statement.
*
* @param[in] target Jump target.
* @param[in] a Address.
*
* @par Preconditions
*  - @a target is non-null
*/
GotoStmt* GotoStmt::create(Statement* target, Address a) {
	PRECONDITION_NON_NULL(target);

	GotoStmt* gotoStmt(new GotoStmt(target, a));

	// Initialization (recall that this, which is called in
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
void GotoStmt::update(Value* subject, Value* arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	Statement* newTarget = cast<Statement>(arg);
	if (arg && !newTarget) {
		return;
	}

	if (subject == target) {
		setTarget(newTarget);
	}
}

void GotoStmt::accept(Visitor *v) {
	v->visit(ucast<GotoStmt>(this));
}

} // namespace llvmir2hll
} // namespace retdec
