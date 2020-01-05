/**
* @file include/retdec/llvmir2hll/ir/const_struct.h
* @brief A struct constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_STRUCT_H
#define RETDEC_LLVMIR2HLL_IR_CONST_STRUCT_H

#include <utility>
#include <vector>

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class ConstInt;
class Expression;
class Visitor;
class StructType;

/**
* @brief A struct constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstStruct final: public Constant {
public:
	/// A single struct item (field name, value)
	using Item = std::pair<ConstInt*, Expression*>;

	/// Underlying type for a struct constant.
	using Type = std::vector<Item>;

public:
	static ConstStruct* create(Type value, StructType* type);

	virtual Value* clone() override;

	virtual bool isEqualTo(Value* otherValue) const override;
	virtual retdec::llvmir2hll::Type* getType() const override;
	virtual void replace(Expression* oldExpr,
		Expression* newExpr) override;

	Type getValue() const;

	/// @name Observer Interface
	/// @{
	virtual void update(Value* subject,
		Value* arg = nullptr) override;
	/// @}

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

    static bool classof(const Value* v) {
        return v->getKind() == Value::ValueKind::ConstStruct; }

private:
	/// Value of the constant.
	Type value;

	/// Type of the value.
	StructType* type = nullptr;

private:
	// Since instances are created by calling the static function create(),
	// constructors can be private.
	ConstStruct(Type value, StructType* type);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
