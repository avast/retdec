/**
* @file include/retdec/llvmir2hll/ir/const_bool.h
* @brief A bool constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_BOOL_H
#define RETDEC_LLVMIR2HLL_IR_CONST_BOOL_H

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class IntType;
class Visitor;

/**
* @brief A bool constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstBool final: public Constant {
public:
	/// Underlying bool type.
	using Type = bool;

public:
	static ConstBool* create(Type value = Type());

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual retdec::llvmir2hll::Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	Type getValue() const;
	bool isTrue() const;
	bool isFalse() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Value of the constant.
	Type value;

	/// Type of the constant.
	IntType* type = nullptr;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit ConstBool(Type value = Type());
};

} // namespace llvmir2hll
} // namespace retdec

#endif
