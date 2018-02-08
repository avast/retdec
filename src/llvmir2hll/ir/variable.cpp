/**
* @file src/llvmir2hll/ir/variable.cpp
* @brief Implementation of Variable.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/type.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new variable.
*
* See create() for more information.
*/
Variable::Variable(const std::string &name, ShPtr<Type> type):
	initialName(name), name(name), type(type), internal(true) {}

/**
* @brief Destructs the variable.
*/
Variable::~Variable() {}

ShPtr<Value> Variable::clone() {
	// Variables are not cloned (see the description of Value::clone()).
	return shared_from_this();
}

bool Variable::isEqualTo(ShPtr<Value> otherValue) const {
	// Both types, names, and internal status have to be equal.
	if (ShPtr<Variable> otherVariable = cast<Variable>(otherValue)) {
		return initialName == otherVariable->initialName &&
			name == otherVariable->name &&
			type->isEqualTo(otherVariable->type) &&
			internal == otherVariable->internal;
	}
	return false;
}

void Variable::replace(ShPtr<Expression> oldExpr, ShPtr<Expression> newExpr) {
	PRECONDITION_NON_NULL(oldExpr);

	// There is nothing to be replaced.
}

/**
* @brief Returns the initial name of the variable.
*
* This is the name that was assigned to the variable before any renaming.
*/
const std::string &Variable::getInitialName() const {
	return initialName;
}

/**
* @brief Returns the name of the variable.
*/
const std::string &Variable::getName() const {
	return name;
}

/**
* @brief Returns @c true if the variable has name, @c false otherwise.
*/
bool Variable::hasName() const {
	return !name.empty();
}

/**
* @brief Returns the type of the variable.
*/
ShPtr<Type> Variable::getType() const {
	return type;
}

/**
* @brief Returns @c true if the variable is internal, @c false otherwise.
*
* An @e internal variable is a variable for which we have complete information,
* i.e. we know all its uses and it cannot be modified on other places. If a
* variable is not internal, it is an @e external variable.
*
* Currently, we use this flag for the following purposes:
*
*  - Internal variables correspond to variables that either have 'internal
*    linkage' in LLVM IR or are ordinary local variables.
*  - External variables correspond to variables that either have 'external
*    linkage' or are used in a volatile load/store operation.
*
* By default, variables are created as internal variables. To make them
* external, call @c markAsExternal().
*/
bool Variable::isInternal() const {
	return internal;
}

/**
* @brief Returns @c true if the variable is external, @c false otherwise.
*
* See the description of isInternal() for more details.
*/
bool Variable::isExternal() const {
	return !internal;
}

/**
* @brief Returns a copy of this variable.
*
* Since clone() does not clone variables (see the description of
* Value::clone()), this function may be used instead to create a copy of the
* variable.
*/
ShPtr<Variable> Variable::copy() const {
	ShPtr<Variable> varCopy(Variable::create(initialName, type));
	varCopy->setName(name);
	varCopy->internal = internal;
	return varCopy;
}

/**
* @brief Sets the variable's name to @a newName.
*/
void Variable::setName(const std::string &newName) {
	name = newName;
}

/**
* @brief Sets the variable's type to @a newType.
*
* @par Preconditions
*  - @a newType is non-null
*/
void Variable::setType(ShPtr<Type> newType) {
	PRECONDITION_NON_NULL(newType);

	type = std::move(newType);
}

/**
* @brief Sets the variable as internal.
*
* See the description of isInternal() for more information about the meaning of
* internal variables.
*/
void Variable::markAsInternal() {
	internal = true;
}

/**
* @brief Sets the variable as external.
*
* See the description of isExternal() for more information about the meaning of
* external variables.
*/
void Variable::markAsExternal() {
	internal = false;
}

/**
* @brief Creates a new variable.
*
* @param[in] name Name of the variable.
* @param[in] type Type of the variable.
*
* By default, the created variable is internal. See isInternal() for more
* details.
*
* @par Preconditions
*  - @a type is non-null
*/
ShPtr<Variable> Variable::create(const std::string &name, ShPtr<Type> type) {
	PRECONDITION_NON_NULL(type);

	// Currently, there is no special initialization.
	return ShPtr<Variable>(new Variable(name, type));
}

void Variable::accept(Visitor *v) {
	v->visit(ucast<Variable>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
