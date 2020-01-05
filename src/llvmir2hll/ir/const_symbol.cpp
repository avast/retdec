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
ConstSymbol::ConstSymbol(const std::string &name, Constant* value):
	Constant(), name(name), value(value) {}

Value* ConstSymbol::clone() {
	ConstSymbol* constSymbol(ConstSymbol::create(name, value));
	constSymbol->setMetadata(getMetadata());
	return constSymbol;
}

bool ConstSymbol::isEqualTo(Value* otherValue) const {
	// Both names and values have to be equal.
	if (ConstSymbol* otherConstSymbol = cast<ConstSymbol>(otherValue)) {
		return name == otherConstSymbol->getName() &&
			value->isEqualTo(otherConstSymbol->getValue());
	}
	return false;
}

Type* ConstSymbol::getType() const {
	return value->getType();
}

void ConstSymbol::replace(Expression* oldExpr, Expression* newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	Constant* constOldExpr(cast<Constant>(oldExpr));
	if (!constOldExpr || value != constOldExpr) {
		return;
	}

	Constant* constNewExpr(cast<Constant>(newExpr));
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
ConstSymbol* ConstSymbol::create(const std::string &name,
		Constant* value) {
	PRECONDITION_NON_NULL(value);

	ConstSymbol* constSymbol(new ConstSymbol(name, value));

	// Initialization (recall that this cannot be called in a
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
Constant* ConstSymbol::getValue() const {
	return value;
}

/**
* @brief Sets a new value of the constant.
*
* @par Preconditions
*  - @a newValue is non-null
*/
void ConstSymbol::setValue(Constant* newValue) {
	PRECONDITION_NON_NULL(newValue);

	value->removeObserver(this);
	value = newValue;
	value->addObserver(this);
}

void ConstSymbol::accept(Visitor *v) {
	v->visit(ucast<ConstSymbol>(this));
}

} // namespace llvmir2hll
} // namespace retdec
