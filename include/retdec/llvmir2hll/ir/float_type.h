/**
* @file include/retdec/llvmir2hll/ir/float_type.h
* @brief A representation of an floatong point types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_FLOAT_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_FLOAT_TYPE_H

#include <map>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of an float point type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class FloatType final: public Type {
public:
	static ShPtr<FloatType> create(unsigned size);

	virtual ~FloatType() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	unsigned getSize() const;

	bool existsFloatTypeWith(unsigned size) const;

	bool existsFloatType() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Mapping of float point type sizes into FloatType instances.
	using SizeToFloatTypeMap = std::map<unsigned, ShPtr<FloatType>>;

private:
	/// Number of bits (size of the float point type).
	unsigned size;

	/// Set of already created float point types of the given size.
	static SizeToFloatTypeMap createdTypes;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	FloatType(unsigned size);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
