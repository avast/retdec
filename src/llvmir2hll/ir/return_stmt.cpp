/**
* @file src/llvmir2hll/ir/return_stmt.cpp
* @brief Implementation of ReturnStmt.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new return statement.
*
* See create() for more information.
*/
ReturnStmt::ReturnStmt(ShPtr<Expression> retVal): retVal(retVal) {}

/**
* @brief Destructs the statement.
*/
ReturnStmt::~ReturnStmt() {}

ShPtr<Value> ReturnStmt::clone() {
	ShPtr<ReturnStmt> returnStmt(ReturnStmt::create());
	returnStmt->setMetadata(getMetadata());
	if (retVal) {
		returnStmt->setRetVal(ucast<Expression>(retVal->clone()));
	}
	return returnStmt;
}

bool ReturnStmt::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types and return values have to be equal.
	if (ShPtr<ReturnStmt> otherReturnStmt = cast<ReturnStmt>(otherValue)) {
		if (!retVal && !otherReturnStmt->retVal) {
			// There are no return values.
			return true;
		} else if (retVal && otherReturnStmt->retVal) {
			return retVal->isEqualTo(otherReturnStmt->retVal);
		}
	}
	return false;
}

void ReturnStmt::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	if (oldExpr == retVal) {
		setRetVal(newExpr);
	} else if (retVal) {
		retVal->replace(oldExpr, newExpr);
	}
}

ShPtr<Expression> ReturnStmt::asExpression() const {
	// Cannot be converted into an expression.
	return {};
}

/**
* @brief Returns the return value.
*/
ShPtr<Expression> ReturnStmt::getRetVal() const {
	return retVal;
}

/**
* @brief Sets a new return value.
*
* @param[in] newRetVal New value to be set.
*
* If @a newRetVal is the null pointer, the return value of the statement is
* discarded.
*/
void ReturnStmt::setRetVal(ShPtr<Expression> newRetVal) {
	if (retVal) {
		retVal->removeObserver(shared_from_this());
	}
	retVal = newRetVal;
	if (retVal) {
		retVal->addObserver(shared_from_this());
	}
}

/**
* @brief Returns @c true if the return statement has return value, @c false
*        otherwise.
*/
bool ReturnStmt::hasRetVal() const {
	return retVal != nullptr;
}

/**
* @brief Creates a new return statement.
*
* @param[in] retVal Return value.
* @param[in] succ Follower of the statement in the program flow.
*/
ShPtr<ReturnStmt> ReturnStmt::create(ShPtr<Expression> retVal, ShPtr<Statement> succ) {
	ShPtr<ReturnStmt> stmt(new ReturnStmt(retVal));
	stmt->setSuccessor(succ);

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	if (retVal) {
		retVal->addObserver(stmt);
	}

	return stmt;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* If @a subject is the current return value, it replaces @a subject with @arg.
*
* This function does nothing when:
*  - @a subject does not correspond to the return value
*  - @a arg is not an expression
*
* @par Preconditions
*  - @a subject is non-null
*
* @see Subject::update()
*/
void ReturnStmt::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);

	ShPtr<Expression> newRetVal = cast<Expression>(arg);
	if (subject == retVal && (!arg || newRetVal)) {
		setRetVal(newRetVal);
	}
}

void ReturnStmt::accept(Visitor *v) {
	v->visit(ucast<ReturnStmt>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
