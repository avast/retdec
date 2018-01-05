/**
* @file src/llvmir2hll/obtainer/calls_obtainer.cpp
* @brief Implementation of CallsObtainer.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/obtainer/calls_obtainer.h"
#include "retdec/llvmir2hll/support/debug.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new obtainer.
*/
CallsObtainer::CallsObtainer():
	OrderedAllVisitor(false, false), foundCalls() {}

/**
* @brief Destructs the obtainer.
*/
CallsObtainer::~CallsObtainer() {}

/**
* @brief Returns a list of all function calls in the given @a value.
*
* Nested function calls are not considered, e.g. for
* @code
* func1(1, 2, func2("test"), var) + func3()
* @endcode
* it returns
* @code
* [func1(1, 2, func2("test"), var), func3()]
* @endcode
*
* If @a value is a statement, nested statements or successors are not visited.
*
* Function calls are obtained from the left to the right (i.e. in the order
* Visitor visits them).
*
* @par Preconditions
*  - @a value is non-null
*/
CallVector CallsObtainer::getCalls(ShPtr<Value> value) {
	PRECONDITION_NON_NULL(value);

	ShPtr<CallsObtainer> obtainer(new CallsObtainer());
	value->accept(obtainer.get());
	return obtainer->foundCalls;
}

/**
* @brief Returns @c true if the selected @a value contains some function calls,
*        @c false otherwise.
*
* See the description of getCalls() for more information.
*/
bool CallsObtainer::hasCalls(ShPtr<Value> value) {
	return !CallsObtainer::getCalls(value).empty();
}

void CallsObtainer::visit(ShPtr<CallExpr> expr) {
	foundCalls.push_back(expr);
}

} // namespace llvmir2hll
} // namespace retdec
