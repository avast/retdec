/**
* @file src/ctypes/function_type.cpp
* @brief Implementation of FunctionType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/visitor.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new function type.
*/
FunctionType::FunctionType(
	const std::shared_ptr<Type> &returnType,
	const Parameters &parameters,
	const CallConvention &callConvention,
	VarArgness varArgness):
	Type(), returnType(returnType), parameters(parameters),
	callConvention(callConvention), varArgness(varArgness) {}

/**
* @brief Creates function type.
*
* @param context Storage for already created functions, types.
* @param returnType Function type return type.
* @param parameters Function type parameters types.
* @param callConvention Function type call convention.
* @param varArgness Info that function takes variable number of arguments or not.
*
* @par Preconditions
*  - @a context is not null
*  - @a returnType is not null
*
* Does not create new function type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<FunctionType> FunctionType::create(
	const std::shared_ptr<Context> &context,
	const std::shared_ptr<Type> &returnType,
	const Parameters &parameters,
	const CallConvention &callConvention,
	VarArgness varArgness)
{
	assert(context && "violated precondition - context cannot be null");
	assert(returnType && "violated precondition - returnType cannot be null");

	auto type = context->getFunctionType(returnType, parameters);
	if (type)
	{
		return type;
	}

	std::shared_ptr<FunctionType> newType(
		new FunctionType(returnType, parameters, callConvention, varArgness));
	context->addFunctionType(newType);
	return newType;
}

/**
* @brief Returns function's return type.
*/
std::shared_ptr<Type> FunctionType::getReturnType() const
{
	return returnType;
}

/**
* @brief Returns an iterator to the parameter.
*/
FunctionType::parameter_iterator FunctionType::parameter_begin()
{
	return parameters.begin();
}

/**
* @brief Returns a constant iterator to the parameter.
*/
FunctionType::const_parameter_iterator FunctionType::parameter_begin() const
{
	return parameters.begin();
}

/**
* @brief Returns an iterator past the last parameter.
*/
FunctionType::parameter_iterator FunctionType::parameter_end()
{
	return parameters.end();
}

/**
* @brief Returns a constant iterator past the last parameter.
*/
FunctionType::const_parameter_iterator FunctionType::parameter_end() const
{
	return parameters.end();
}

/**
* @brief Returns the number of parameters.
*
* Does not matter if function takes variable number of parameters or not.
*/
FunctionType::Parameters::size_type FunctionType::getParameterCount() const
{
	return parameters.size();
}

/**
* @brief Returns function type parameters.
*/
const FunctionType::Parameters &FunctionType::getParameters() const
{
	return parameters;
}

/**
* @brief Returns the n-th parameter's type.
*
* @par Preconditions
*  - <tt>0 < n <= ParameterCount</tt>
*
* The parameters are numbered starting with @c 1.
*/
std::shared_ptr<Type> FunctionType::getParameter(Parameters::size_type n) const
{
	return retdec::utils::getNthItem(parameters, n);
}

/**
* @brief Returns @c true if function takes variable number of arguments,
*        @c false otherwise.
*/
bool FunctionType::isVarArg() const
{
	return varArgness == VarArgness::IsVarArg;
}

/**
* @brief Sets function type's call convention.
*/
void FunctionType::setCallConvention(const CallConvention &callConvention)
{
	this->callConvention = callConvention;
}

/**
* @brief Returns function type's call convention.
*/
const CallConvention &FunctionType::getCallConvention() const
{
	return callConvention;
}

/**
* Returns @c true when Type is function type, @c false otherwise.
*/
bool FunctionType::isFunction() const
{
	return true;
}

void FunctionType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<FunctionType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
