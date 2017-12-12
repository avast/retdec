/**
* @file include/llvmir2hll/ir/pointer_type.h
* @brief A representation of a pointer type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_IR_POINTER_TYPE_H
#define LLVMIR2HLL_IR_POINTER_TYPE_H

#include "llvmir2hll/ir/type.h"
#include "llvmir2hll/support/smart_ptr.h"

namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of a pointer type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class PointerType final: public Type {
public:
	static ShPtr<PointerType> create(ShPtr<Type> containedType);

	virtual ~PointerType() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	void setContainedType(ShPtr<Type> newContainedType);
	ShPtr<Type> getContainedType() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Contained type.
	ShPtr<Type> containedType;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	PointerType(ShPtr<Type> containedType);
};

} // namespace llvmir2hll

#endif
