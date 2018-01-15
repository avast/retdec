/**
* @file include/retdec/llvmir2hll/ir/int_type.h
* @brief A representation of an integer type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_INT_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_INT_TYPE_H

#include <map>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of an integer type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class IntType final: public Type {
public:
	static ShPtr<IntType> create(unsigned size, bool isSigned = true);

	virtual ~IntType() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	unsigned getSize() const;
	bool isSigned() const;
	bool isUnsigned() const;
	bool isBool() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Mapping of integer sizes into IntType instances.
	using SizeToIntTypeMap = std::map<unsigned, ShPtr<IntType>>;

private:
	/// Number of bits (size of the integer).
	unsigned size;

	/// Is the integer signed?
	bool signedInt;

	/// Set of already created signed integer types of the given size.
	static SizeToIntTypeMap createdSignedTypes;

	/// Set of already created unsigned integer types of the given size.
	static SizeToIntTypeMap createdUnsignedTypes;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	IntType(unsigned size, bool isSigned = false);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
