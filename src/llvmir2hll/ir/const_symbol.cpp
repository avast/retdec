/**
* @file src/llvmir2hll/ir/const_symbol.cpp
* @brief Implementation of ConstSymbol.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a symbolic constant.
*
* See create() for more information.
*/
ConstSymbol::ConstSymbol(const std::string &name, ShPtr<Constant> value):
	Constant(), name(name), value(value) {}

/**
* @brief Destructs the constant.
*/
ConstSymbol::~ConstSymbol() {}

ShPtr<Value> ConstSymbol::clone() {
	ShPtr<ConstSymbol> constSymbol(ConstSymbol::create(name, value));
	constSymbol->setMetadata(getMetadata());
	return constSymbol;
}

bool ConstSymbol::isEqualTo(ShPtr<Value> otherValue) const {
	// Both names and values have to be equal.
	if (ShPtr<ConstSymbol> otherConstSymbol = cast<ConstSymbol>(otherValue)) {
		return name == otherConstSymbol->getName() &&
			value->isEqualTo(otherConstSymbol->getValue());
	}
	return false;
}

ShPtr<Type> ConstSymbol::getType() const {
	return value->getType();
}

void ConstSymbol::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	ShPtr<Constant> constOldExpr(cast<Constant>(oldExpr));
	if (!constOldExpr || value != constOldExpr) {
		return;
	}

	ShPtr<Constant> constNewExpr(cast<Constant>(newExpr));
	if (!constNewExpr) {
		return;
	}

	setValue(constNewExpr);
}

/**
* @brief Constructs a symbolic constant with the given name and value.
*
* @param[in] name Name of the constant
* @param[in] value Value of the constant.
*
* @par Preconditions
*  - @a value is non-null
*/
ShPtr<ConstSymbol> ConstSymbol::create(const std::string &name,
		ShPtr<Constant> value) {
	PRECONDITION_NON_NULL(value);

	ShPtr<ConstSymbol> constSymbol(new ConstSymbol(name, value));

	// Initialization (recall that shared_from_this() cannot be called in a
	// constructor).
	value->addObserver(constSymbol);

	return constSymbol;
}

/**
* @brief Returns the name of the symbolic constant.
*/
const std::string &ConstSymbol::getName() const {
	return name;
}

/**
* @brief Returns the value of the symbolic constant.
*/
ShPtr<Constant> ConstSymbol::getValue() const {
	return value;
}

/**
* @brief Sets a new value of the constant.
*
* @par Preconditions
*  - @a newValue is non-null
*/
void ConstSymbol::setValue(ShPtr<Constant> newValue) {
	PRECONDITION_NON_NULL(newValue);

	value->removeObserver(shared_from_this());
	value = newValue;
	value->addObserver(shared_from_this());
}

void ConstSymbol::accept(Visitor *v) {
	v->visit(ucast<ConstSymbol>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
