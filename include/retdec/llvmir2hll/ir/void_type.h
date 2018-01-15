/**
* @file include/retdec/llvmir2hll/ir/void_type.h
* @brief A representation of an void type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_VOID_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_VOID_TYPE_H

#include <cstddef>
#include <map>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of an void type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class VoidType final: public Type {
public:
	static ShPtr<VoidType> create();

	virtual ~VoidType() override;

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
	VoidType();
};

} // namespace llvmir2hll
} // namespace retdec

#endif
