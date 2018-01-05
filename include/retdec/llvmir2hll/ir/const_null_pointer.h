/**
* @file include/retdec/llvmir2hll/ir/const_null_pointer.h
* @brief A null pointer constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_NULL_POINTER_H
#define RETDEC_LLVMIR2HLL_IR_CONST_NULL_POINTER_H

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;
class PointerType;

/**
* @brief A null pointer constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstNullPointer final: public Constant {
public:
	static ShPtr<ConstNullPointer> create(ShPtr<PointerType> type);

	virtual ~ConstNullPointer() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Type of the constant.
	ShPtr<PointerType> type;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit ConstNullPointer(ShPtr<PointerType> type);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
