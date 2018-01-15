/**
* @file include/retdec/llvmir2hll/ir/expression.h
* @brief A base class of all expressions.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_EXPRESSION_H
#define RETDEC_LLVMIR2HLL_IR_EXPRESSION_H

#include "retdec/llvmir2hll/ir/value.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Type;

/**
* @brief A base class of all expressions.
*
* Instances of this class have reference object semantics.
*/
class Expression: public Value {
public:
	virtual ~Expression() override;

	/**
	* @brief Returns the type of the expression.
	*
	* If an appropriate type cannot be detected, @c UnknownType is returned.
	* This may happen, for example, when a binary operator have its operands of
	* incompatible type.
	*/
	virtual ShPtr<Type> getType() const = 0;

	/**
	* @brief Replaces all occurrences of @a oldExpr with @a newExpr in the
	*        current expression.
	*
	* @param[in] oldExpr Old expression to be replaced.
	* @param[in] newExpr Replacement.
	*
	* Note that if @a oldExpr is the current expression on which this function
	* is called, nothing gets replaced, i.e. the replacements are done only in
	* the members of the current expression on which this function is called.
	*
	* @par Preconditions
	*  - @a oldExpr is non-null
	*/
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) = 0;

	static void replaceExpression(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr);

protected:
	Expression();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
