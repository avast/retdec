/**
* @file include/retdec/llvmir2hll/ir/const_string.h
* @brief A generic string constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_STRING_H
#define RETDEC_LLVMIR2HLL_IR_CONST_STRING_H

#include <cstdint>
#include <string>

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;
class StringType;

/**
* @brief A generic string constant.
*
* It can hold strings with characters of an arbitrary size.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstString final: public Constant {
public:
	/// Underlying character type.
	using UnderlyingCharType = retdec::utils::WideCharType;

	/// Underlying string type.
	using UnderlyingStringType = retdec::utils::WideStringType;

public:
	static ConstString* create(const UnderlyingStringType &value, std::size_t charSize);
	static ConstString* create(const std::string &str);

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	UnderlyingStringType getValue() const;
	std::string getValueAsEscapedCString() const;
	std::size_t getCharSize() const;
	bool is8BitString() const;
	bool isWideString() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

	static bool classof(const Value* v) {
		return v->getKind() == Value::ValueKind::ConstString; }

private:
	/// Value.
	UnderlyingStringType value;

	// How large are characters in the string (in bits)?
	std::size_t charSize;

	/// Type.
	StringType* type = nullptr;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ConstString(const UnderlyingStringType &value, std::size_t charSize);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
