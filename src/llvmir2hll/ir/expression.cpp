/**
* @file src/llvmir2hll/ir/expression.cpp
* @brief Implementation of Expression.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new expression.
*/
Expression::Expression() {}

/**
* @brief Destructs the expression.
*/
Expression::~Expression() {}

/**
* @brief Replaces @a oldExpr with @a newExpr.
*
* @param[in] oldExpr Old expression to be replaced.
* @param[in] newExpr Replacement.
*
* If you want to replace @a oldExpr with @a newExpr only in a single expression
* (@c where), then use <tt>where->replace(oldExpr, newExpr)</tt>. However, if
* @c where is identical to @a oldExpr, then it has to be replaced manually. For
* example, if @c where is the return value of a return statement @c stmt, the
* following code can be used:
* @code
* if (retVal == oldExpr) {
*     returnStmt->setRetVal(newExpr);
* } else {
*     retVal->replace(oldExpr, newExpr);
* }
* @endcode
*
* @par Preconditions
*  - @a oldExpr is non-null
*/
void Expression::replaceExpression(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// If both expressions are identical, we don't have to do anything.
	if (oldExpr == newExpr) {
		return;
	}

	// Use the observer/subject interface to replace it in all
	// expressions/statements which contain it.
	oldExpr->notifyObservers(newExpr);
}

} // namespace llvmir2hll
} // namespace retdec
