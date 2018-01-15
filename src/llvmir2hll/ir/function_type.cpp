/*;*
* @file src/llvmir2hll/ir/function_type.cpp
* @brief Implementation of FunctionType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/visitor.h"
#include "retdec/utils/container.h"

using retdec::utils::getNthItem;

namespace retdec {
namespace llvmir2hll {

/**
* @brief Constructs a new function type.
*
* See create() for more information.
*/
FunctionType::FunctionType(ShPtr<Type> retType):
	Type(), retType(retType), varArg(false) {}

/**
* @brief Destructs the type.
*/
FunctionType::~FunctionType() {}

ShPtr<Value> FunctionType::clone() {
	ShPtr<FunctionType> cloned(FunctionType::create());
	cloned->retType = retType;
	cloned->varArg = varArg;
	cloned->params = params;
	return cloned;
}

bool FunctionType::isEqualTo(ShPtr<Value> otherValue) const {
	// The types of compared instances have to match.
	ShPtr<FunctionType> otherType = cast<FunctionType>(otherValue);
	if (!otherType) {
		return false;
	}

	// The return types have to match.
	if (!getRetType()->isEqualTo(otherType->getRetType())) {
		return false;
	}

	// The variable number of arguments indications have to match.
	if (isVarArg() != otherType->isVarArg()) {
		return false;
	}

	// The number of parameters have to match.
	if (getNumOfParams() != otherType->getNumOfParams()) {
		return false;
	}

	// All parameters have to match.
	for (param_iterator i = params.begin(), e = params.end(),
			j = otherType->params.begin(); i != e; ++i, ++j) {
		if (!(*i)->isEqualTo(*j)) {
			return false;
		}
	}

	return true;
}

/**
* @brief Sets a new return type.
*/
void FunctionType::setRetType(ShPtr<Type> retType) {
	this->retType = retType;
}

/**
* @brief Returns the return type.
*/
ShPtr<Type> FunctionType::getRetType() const {
	return retType;
}

/**
* @brief Returns @c true if the function has some parameters, @c false
*        otherwise.
*
* The fact whether the function takes a variable number of arguments does not
* have any effect.
*/
bool FunctionType::hasParams() const {
	return !params.empty();
}

/**
* @brief Returns @c true if there is an n-th parameter, @c false otherwise.
*
* The parameters are numbered starting with @c 1.
*/
bool FunctionType::hasParam(std::size_t n) const {
	return n >= 1 && n <= getNumOfParams();
}

/**
* @brief Returns the number of parameters.
*
* The fact whether the function takes a variable number of arguments does not
* have any effect.
*/
std::size_t FunctionType::getNumOfParams() const {
	return params.size();
}

/**
* @brief Adds a new parameter.
*/
void FunctionType::addParam(ShPtr<Type> paramType) {
	params.push_back(paramType);
}

/**
* @brief Returns the n-th parameter.
*
* The parameters are numbered starting with @c 1.
*
* @par Preconditions
*  - <tt>0 < n <= NUM_OF_PARAMS</tt>, where @c NUM_OF_PARAMS is the number of
*    parameters that the function has
*/
ShPtr<Type> FunctionType::getParam(std::size_t n) const {
	PRECONDITION(n > 0, "n `" << n << "` is not > 0");
	PRECONDITION(n <= getNumOfParams(), "n `" << n << "`" << " is greater "
		"than the number of parameters (`" << getNumOfParams() << "`)");

	return getNthItem(params, n);
}

/**
* @brief Returns a constant iterator to the parameter.
*/
FunctionType::param_iterator FunctionType::param_begin() const {
	return params.begin();
}

/**
* @brief Returns a constant iterator past the last parameter.
*/
FunctionType::param_iterator FunctionType::param_end() const {
	return params.end();
}

/**
* @brief Sets the function either as taking a variable number of arguments or
*        not.
*/
void FunctionType::setVarArg(bool isVarArg) {
	varArg = isVarArg;
}

/**
* @brief Returns @c true if the function takes a variable number of arguments,
*        @c false otherwise.
*/
bool FunctionType::isVarArg() const {
	return varArg;
}

/**
* @brief Creates a new function type.
*/
ShPtr<FunctionType> FunctionType::create(ShPtr<Type> retType) {
	return ShPtr<FunctionType>(new FunctionType(retType));
}

void FunctionType::accept(Visitor *v) {
	v->visit(ucast<FunctionType>(shared_from_this()));
}

} // namespace llvmir2hll
} // namespace retdec
