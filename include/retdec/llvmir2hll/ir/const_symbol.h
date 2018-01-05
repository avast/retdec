/**
* @file include/retdec/llvmir2hll/ir/const_symbol.h
* @brief A symbolic constant.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_IR_CONST_SYMBOL_H
#define RETDEC_LLVMIR2HLL_IR_CONST_SYMBOL_H

#include <string>

#include "retdec/llvmir2hll/ir/constant.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"

namespace retdec {
namespace llvmir2hll {

class Expression;
class Visitor;

/**
* @brief A symbolic constant.
*
* Use create() to create instances. Instances of this class have reference
* object semantics. This class is not meant to be subclassed.
*/
class ConstSymbol final: public Constant {
public:
	static ShPtr<ConstSymbol> create(const std::string &name,
		ShPtr<Constant> value);

	virtual ~ConstSymbol() override;

	virtual ShPtr<Value> clone() override;
	virtual bool isEqualTo(ShPtr<Value> otherValue) const override;
	virtual ShPtr<Type> getType() const override;
	virtual void replace(ShPtr<Expression> oldExpr,
		ShPtr<Expression> newExpr) override;

	const std::string &getName() const;
	ShPtr<Constant> getValue() const;

	/// @name Visitor Interface
	/// @{
	virtual void accept(Visitor *v) override;
	/// @}

private:
	/// Name of the constant.
	std::string name;

	/// Value of the constant.
	ShPtr<Constant> value;

private:
	// Since instances are created by calling the static function create(), the
	// constructor can be private.
	ConstSymbol(const std::string &name, ShPtr<Constant> value);

	void setValue(ShPtr<Constant> newValue);
};

} // namespace llvmir2hll
} // namespace retdec

#endif
