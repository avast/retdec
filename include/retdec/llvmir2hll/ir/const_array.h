/**
* @file include/retdec/llvmir2hll/ir/const_array.h
* @brief An array constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_ARRAY_H
#define RETDEC_LLVMIR2HLL_IR_CONST_ARRAY_H

#include <cstddef>
#include <vector>

#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief An array constant.
*
* Use create() or createUninitialized() to create instances. Instances of this
* class have reference object semantics. This class is not meant to be
* subclassed.
*/
class ConstArray final: public Constant {
public:
	/// Underlying type of the array's value.
	using ArrayValue = std::vector<Expression*>;

	/// Initialized array iterator.
	using init_iterator = ArrayValue::const_iterator;

public:
	static ConstArray* create(ArrayValue value, ArrayType* type);
	static ConstArray* createUninitialized(ArrayType* type);

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	bool isInitialized() const;
	bool isEmpty() const;
	Type* getContainedType() const;
	ArrayType::Dimensions getDimensions() const;

	/// @name Initialized Array Accessors
	/// @{
	const ArrayValue &getInitializedValue() const;

	init_iterator init_begin() const;
	init_iterator init_end() const;
	/// @}

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Value of an initialized array.
	ArrayValue value;

	/// Is the array initialized?
	bool initialized;

	/// The type of the array.
	ArrayType* type = nullptr;

private:
	// Since instances are created by calling the static function create(),
	// constructors can be private.
	ConstArray(ArrayValue value, ArrayType* type);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
