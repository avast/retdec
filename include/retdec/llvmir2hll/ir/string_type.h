/**
* @file include/retdec/llvmir2hll/ir/string_type.h
* @brief A representation of a string type.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_STRING_TYPE_H
#define RETDEC_LLVMIR2HLL_IR_STRING_TYPE_H

#include <cstdint>
#include <map>

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Visitor;

/**
* @brief A representation of a string type.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class StringType final: public Type {
public:
	static ShPtr<StringType> create(std::size_t charSize);

	virtual ~StringType() override;

	virtual ShPtr<Value> clone() override;

	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;

	std::size_t getCharSize() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Mapping of sizes into StringType instances.
	using SizeToStringTypeMap = std::map<std::size_t, ShPtr<StringType>>;

private:
	/// How large are characters in the string (in bits)?
	std::size_t charSize;

	/// Set of already created string types with characters of the given size.
	static SizeToStringTypeMap createdTypes;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	explicit StringType(std::size_t charSize);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
