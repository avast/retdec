/**
* @file include/retdec/llvmir2hll/ir/array_type.h
* @brief A representation of an array type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_ARRAY_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_ARRAY_TYPE_H

#include <cstddef>
#include <vector>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of an array type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ArrayType final: public Type {
public:
	/// Array dimensions.
	using Dimensions = std::vector<std::size_t>;

public:
	static ShPtr<ArrayType> create(ShPtr<Type> elemType, const Dimensions &dims);

	virtual ~ArrayType() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	ShPtr<Type> getContainedType() const;
	Dimensions getDimensions() const;
	bool hasEmptyDimensions() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Type of elements of the array.
	ShPtr<Type> elemType;

	/// Array dimensions.
	Dimensions dims;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ArrayType(ShPtr<Type> elemType, const Dimensions &dims);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
