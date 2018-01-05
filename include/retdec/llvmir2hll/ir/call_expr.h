/**
* @file include/retdec/llvmir2hll/ir/call_expr.h
* @brief A call expression.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CALL_EXPR_H
#define RETDEC_LLVMIR2HLL_IR_CALL_EXPR_H

#include <cstddef>

#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A call expression.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class CallExpr final: public Expression {
public:
	static ShPtr<CallExpr> create(ShPtr<Expression> calledExpr,
		ExprVector args = ExprVector());

	virtual ~CallExpr() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	ShPtr<Expression> getCalledExpr() const;
	bool hasArg(std::size_t n) const;
	ShPtr<Expression> getArg(std::size_t n) const;
	const ExprVector &getArgs() const;
	std::size_t getNumOfArgs() const;

	void setCalledExpr(ShPtr<Expression> newCalledExpr);
	void setArgs(ExprVector newArgs);
	void setArg(std::size_t position, ShPtr<Expression> newArg);
	void replaceArg(ShPtr<Expression> oldArg, ShPtr<Expression> newArg);

	/// @name Observer Interface
	/// @{
	virtual void update(ShPtr<Value> subject,
		ShPtr<Value> arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	CallExpr(ShPtr<Expression> calledExpr, ExprVector args);

private:
	/// Expression that is called by this call.
	ShPtr<Expression> calledExpr;

	/// Arguments.
	ExprVector args;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
