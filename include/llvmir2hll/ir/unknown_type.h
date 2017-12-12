/**
* @file include/llvmir2hll/ir/unknown_type.h
* @brief A representation of an Unknown type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef LLVMIR2HLL_IR_UNKNOWN_TYPE_H
#define LLVMIR2HLL_IR_UNKNOWN_TYPE_H

#include <cstddef>
#include <map>

#include "llvmir2hll/ir/type.h"
#include "llvmir2hll/support/smart_ptr.h"

namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of an Unknown type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class UnknownType final: public Type {
public:
	static ShPtr<UnknownType> create();

	virtual ~UnknownType() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	std::size_t getSize() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	UnknownType();
};

} // namespace llvmir2hll

#endif
