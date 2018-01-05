/**
* @file include/retdec/llvmir2hll/ir/struct_type.h
* @brief A representation of a structured type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_STRUCT_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_STRUCT_TYPE_H

#include <map>
#include <vector>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ConstInt;
class Visitor;

/**
* @brief A representation of a structured type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class StructType final: public Type {
public:
	/// Vector of types of elements in the structure.
	using ElementTypes = std::vector<ShPtr<Type>>;

public:
	static ShPtr<StructType> create(ElementTypes elementTypes,
		const std::string &name = "");

	virtual ~StructType() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	const ElementTypes &getElementTypes() const;
	const ShPtr<Type> getTypeOfElement(ShPtr<ConstInt> index) const;
	bool hasName() const;
	const std::string &getName() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	StructType(ElementTypes elementTypes, const std::string &name);

private:
	/// Types of elements in the structure.
	ElementTypes elementTypes;

	/// Name of the structure.
	std::string name;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
