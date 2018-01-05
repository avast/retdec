/**
* @file src/llvmir2hll/ir/call_expr.cpp
* @brief Implementation of CallExpr.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/container.h"

using retdec::utils::getNthItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new call expression.
*
* See create() for more information.
*/
CallExpr::CallExpr(ShPtr<Expression> calledExpr, ExprVector args):
	calledExpr(calledExpr), args(args) {}

/**
* @brief Destructs the call expression.
*/
CallExpr::~CallExpr() {}

ShPtr<Value> CallExpr::clone() {
	// Clone all arguments.
	ExprVector newArgs;
	for (const auto &arg : args) {
		newArgs.push_back(ucast<Expression>(arg->clone()));
	}

	ShPtr<CallExpr> callExpr(CallExpr::create(
		ucast<Expression>(calledExpr->clone()), newArgs));
	callExpr->setMetadata(getMetadata());
	return callExpr;
}

bool CallExpr::isEqualTo(ShPtr<Value> otherValue) const {
	if (!otherValue) {
		return false;
	}

	// The types of compared instances have to match.
	ShPtr<CallExpr> otherCallExpr = cast<CallExpr>(otherValue);
	if (!otherCallExpr) {
		return false;
	}

	// The called expressions have to match.
	if (!calledExpr->isEqualTo(otherCallExpr->calledExpr)) {
		return false;
	}

	// The number of arguments have to match.
	if (args.size() != otherCallExpr->args.size()) {
		return false;
	}

	// All arguments have to match.
	for (ExprVector::const_iterator i = args.begin(), j = otherCallExpr->args.begin(),
			e = args.end(); i != e; ++i, ++j) {
		if (!(*i)->isEqualTo(*j)) {
			return false;
		}
	}

	return true;
}

ShPtr<Type> CallExpr::getType() const {
	return calledExpr->getType();
}

void CallExpr::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// Called expression.
	if (calledExpr == oldExpr) {
		setCalledExpr(newExpr);
	} else {
		calledExpr->replace(oldExpr, newExpr);
	}

	// Arguments.
	for (auto &arg : args) {
		if (arg == oldExpr) {
			arg->removeObserver(shared_from_this());
			newExpr->addObserver(shared_from_this());
			arg = newExpr;
		} else {
			arg->replace(oldExpr, newExpr);
		}
	}
}

/**
* @brief Returns the expression called by this call.
*/
ShPtr<Expression> CallExpr::getCalledExpr() const {
	return calledExpr;
}

/**
* @brief Returns the argument list.
*/
const ExprVector &CallExpr::getArgs() const {
	return args;
}

/**
* @brief Returns the number of arguments in the call.
*/
std::size_t CallExpr::getNumOfArgs() const {
	return args.size();
}

/**
* @brief Returns @c true if the call has an n-th argument, @c false otherwise.
*
* The arguments are numbered in the following way:
* @code
* func(1, 2, 3, 4, ...)
* @endcode
*/
bool CallExpr::hasArg(std::size_t n) const {
	return n >= 1 && n <= args.size();
}

/**
* @brief Returns the @c n-th argument.
*
* The arguments are numbered in the following way:
* @code
* func(1, 2, 3, 4, ...)
* @endcode
*
* @par Preconditions
*  - <tt>0 < n <= NUM_OF_ARGS</tt>, where @c NUM_OF_ARGS is the number of
*    arguments that the call has
*/
ShPtr<Expression> CallExpr::getArg(std::size_t n) const {
	PRECONDITION(n > 0, "n `" << n << "` is not > 0");
	PRECONDITION(n <= args.size(), "n `" << n << "`" <<
		" is greater than the number of arguments (`" << args.size() << "`)");

	return getNthItem(args, n);
}

/**
* @brief Sets a new called expression.
*
* @par Preconditions
*  - @a newCalledExpr is non-null
*/
void CallExpr::setCalledExpr(ShPtr<Expression> newCalledExpr) {
	PRECONDITION_NON_NULL(newCalledExpr);

	calledExpr->removeObserver(shared_from_this());
	newCalledExpr->addObserver(shared_from_this());
	calledExpr = newCalledExpr;
}

/**
* @brief Sets a new argument list.
*/
void CallExpr::setArgs(ExprVector newArgs) {
	for (auto &arg : args) {
		arg->removeObserver(shared_from_this());
	}
	for (auto &arg : newArgs) {
		arg->addObserver(shared_from_this());
	}
	args = newArgs;
}

/**
* @brief Sets a new argument to the given position.
*
* @param[in] position Position on which the new argument is placed.
* @param[in] newArg New argument.
*
* @par Preconditions
*  - @a position is not out of range
*  - @a newArg is non-null
*/
void CallExpr::setArg(std::size_t position, ShPtr<Expression> newArg) {
	PRECONDITION(position < args.size(),
		"position, which is " << position << ", is out of range");
	PRECONDITION_NON_NULL(newArg);

	// Obtain an iterator to the "position"th argument.
	auto iter = args.begin();
	for (std::size_t j = 0; j < position; ++j) {
		++iter;
	}

	// Replace the argument.
	(*iter)->removeObserver(shared_from_this());
	newArg->addObserver(shared_from_this());
	*iter = newArg;
}

/**
* @brief Replaces @a oldArg with @a newArg.
*
* If @a oldArg does not correspond to any argument, this function does nothing.
*
* @par Preconditions
*  - both arguments are non-null
*/
void CallExpr::replaceArg(ShPtr<Expression> oldArg, ShPtr<Expression> newArg) {
	// Does oldArg correspond to an argument?
	auto oldArgIter = std::find(args.begin(), args.end(), oldArg);
	if (oldArgIter != args.end()) {
		// It does, so replace it.
		oldArg->removeObserver(shared_from_this());
		newArg->addObserver(shared_from_this());
		*oldArgIter = newArg;
	}
}

/**
* @brief Creates a new call expression.
*
* @param[in] calledExpr Expression that is called by this call.
* @param[in] args Argument list.
*
* @par Preconditions
*  - @a calledExpr is non-null
*/
ShPtr<CallExpr> CallExpr::create(ShPtr<Expression> calledExpr, ExprVector args) {
	PRECONDITION_NON_NULL(calledExpr);

	ShPtr<CallExpr> expr(new CallExpr(calledExpr, args));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	calledExpr->addObserver(expr);
	for (auto &arg : args) {
		arg->addObserver(expr);
	}

	return expr;
}

/**
* @brief Updates the statement according to the changes of @a subject.
*
* @param[in] subject Observable object.
* @param[in] arg Optional argument.
*
* Replaces @a subject with @a arg. For example, if @a subject is one of the
* arguments of this call, this function replaces it with @a arg.
*
* This function does nothing when:
*  - @a subject does not correspond to any part of this call
*  - @a arg is not an expression
*
* @par Preconditions
*  - both arguments are non-null
*
* @see Subject::update()
*/
void CallExpr::update(ShPtr<Value> subject, ShPtr<Value> arg) {
	PRECONDITION_NON_NULL(subject);
	PRECONDITION_NON_NULL(arg);

	ShPtr<Expression> newCalledExpr = cast<Expression>(arg);
	if (subject == calledExpr && newCalledExpr) {
		setCalledExpr(newCalledExpr);
		return;
	}

	if (ShPtr<Expression> oldArg = cast<Expression>(subject)) {
		if (ShPtr<Expression> newArg = cast<Expression>(arg)) {
			// If oldArg does not correspond to any argument, replaceArg() does
			// nothing, so the following call is safe.
			replaceArg(oldArg, newArg);
		}
	}
}

void CallExpr::accept(Visitor *v) {
	v->visit(ucast<CallExpr>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
