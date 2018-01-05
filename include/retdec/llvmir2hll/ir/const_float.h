/**
* @file include/retdec/llvmir2hll/ir/const_float.h
* @brief A float constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_FLOAT_H
#define RETDEC_LLVMIR2HLL_IR_CONST_FLOAT_H

#include <string>
#include <utility>

#include <llvm/ADT/APFloat.h>

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class FloatType;
class Visitor;

/**
* @brief A float constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstFloat final: public Constant {
public:
	/// Underlying floating-point type.
	// We use the arbitrary precision floats from LLVM to store constant
	// floats. This way, we don't have to use another 3rd party library or
	// craft some custom code.
	using Type = llvm::APFloat;

public:
	static ShPtr<ConstFloat> create(Type value);

	virtual ~ConstFloat() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<retdec::llvmir2hll::Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	Type getValue() const;
	unsigned getSize() const;
	std::string toString(unsigned precision = 0, unsigned maxPadding = 0) const;
	std::string toMostReadableString() const;

	void flipSign();

	bool isNegative() const;
	bool isNegativeOne() const;
	bool isPositive() const;
	bool isZero() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Arguments of toString().
	using ToStringArgs = std::pair<unsigned, unsigned>;

private:
	/// Value of the constant.
	Type value;

	/// Type of the constant.
	ShPtr<FloatType> type;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit ConstFloat(Type value);

	ToStringArgs getToStringArgsForMostReadableString() const;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
