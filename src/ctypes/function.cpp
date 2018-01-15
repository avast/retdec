/**
* @file src/ctypes/function.cpp
* @brief Implementation of Function.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new function.
*/
Function::Function(
	const std::string &name,
	const std::shared_ptr<FunctionType> &functionType,
	const Parameters &parameters):
	name(name), functionType(functionType), parameters(parameters) {}

const std::string &Function::getName() const
{
	return name;
}

/**
* @brief Returns function's function type - return type and parameters' types.
*/
std::shared_ptr<FunctionType> Function::getType() const
{
	return functionType;
}

/**
* @brief Returns function's return type.
*/
std::shared_ptr<Type> Function::getReturnType() const
{
	return functionType->getReturnType();
}

/**
* @brief Returns an iterator to the parameter.
*/
Function::parameter_iterator Function::parameter_begin()
{
	return parameters.begin();
}

/**
* @brief Returns a constant iterator to the parameter.
*/
Function::const_parameter_iterator Function::parameter_begin() const
{
	return parameters.begin();
}

/**
* @brief Returns an iterator past the last parameter.
*/
Function::parameter_iterator Function::parameter_end()
{
	return parameters.end();
}

/**
* @brief Returns a constant iterator past the last parameter.
*/
Function::const_parameter_iterator Function::parameter_end() const
{
	return parameters.end();
}

/**
* @brief Returns the number of parameters.
*
* Does not matter if function takes variable number of parameters or not.
*/
Function::Parameters::size_type Function::getParameterCount() const
{
	return parameters.size();
}

/**
* @brief Returns the n-th parameter.
*
* @par Preconditions
*  - <tt>0 < n <= ParameterCount</tt>
*
* The parameters are numbered starting with @c 1.
*/
const Parameter &Function::getParameter(Parameters::size_type n) const
{
	return retdec::utils::getNthItem(parameters, n);
}

/**
* @brief Returns the n-th parameter's name.
*
* @par Preconditions
*  - <tt>0 < n <= ParameterCount</tt>
*
* The parameters are numbered starting with @c 1.
*/
const std::string &Function::getParameterName(Parameters::size_type n) const
{
	return getParameter(n).getName();
}

/**
* @brief Returns the n-th parameter's type.
*
* @par Preconditions
*  - <tt>0 < n <= ParameterCount</tt>
*
* The parameters are numbered starting with @c 1.
*/
std::shared_ptr<Type> Function::getParameterType(Parameters::size_type n) const
{
	return getParameter(n).getType();
}

/**
* @brief Returns @c true if function takes variable number of arguments,
*        @c false otherwise.
*/
bool Function::isVarArg() const
{
	return functionType->isVarArg();
}

/**
* @brief Creates function.
*
* @param context Storage for already created functions, types.
* @param name Name of new function.
* @param returnType Function return type.
* @param parameters Function parameters.
* @param callConvention Function call convention.
* @param varArgness Info that function takes variable number of arguments or not.
*
* @par Preconditions
*  - @a context is not null
*  - @a returnType is not null
*
* Does not create new function, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<Function> Function::create(
	const std::shared_ptr<Context> &context,
	const std::string &name,
	const std::shared_ptr<Type> &returnType,
	const Parameters &parameters,
	const CallConvention &callConvention,
	VarArgness varArgness)
{
	assert(context && "violated precondition - context cannot be null");
	assert(returnType && "violated precondition - returnType cannot be null");

	auto function = context->getFunctionWithName(name);
	if (function)
	{
		return function;
	}

	auto funcType = createFunctionType(
		context, returnType, parameters, callConvention, varArgness
	);
	std::shared_ptr<Function> newFunc(
		new Function(name, funcType, parameters)
	);
	context->addFunction(newFunc);
	return newFunc;
}

/**
* @brief Creates function type.
*
* @param context Storage for already created functions, types.
* @param returnType Function return type.
* @param parameters Function parameters.
* @param callConvention Function call convention.
* @param varArgness Info that function takes variable number of arguments or not.
*
* @par Preconditions
*  - @a context is not null
*  - @a returnType is not null
*/
std::shared_ptr<FunctionType> Function::createFunctionType(
	const std::shared_ptr<Context> &context,
	const std::shared_ptr<Type> &returnType,
	const Parameters &parameters,
	const CallConvention &callConvention,
	VarArgness varArgness)
{
	assert(context && "violated precondition - context cannot be null");
	assert(returnType && "violated precondition - returnType cannot be null");

	FunctionType::Parameters paramTypes;
	for (const auto &param: parameters)
	{
		paramTypes.push_back(param.getType());
	}
	return FunctionType::create(context, returnType, paramTypes, callConvention, varArgness);
}

/**
* @brief Sets function's call convention.
*/
void Function::setCallConvention(const CallConvention &callConvention)
{
	functionType->setCallConvention(callConvention);
}

/**
* @brief Returns function's call convention.
*/
const CallConvention &Function::getCallConvention() const
{
	return functionType->getCallConvention();
}

/**
* @brief Sets function declaration.
*/
void Function::setDeclaration(const FunctionDeclaration &declaration)
{
	this->declaration = declaration;
}

/**
* @brief Returns function declaration.
*/
FunctionDeclaration Function::getDeclaration() const
{
	return declaration;
}

/**
* @brief Sets header file of function.
*/
void Function::setHeaderFile(const HeaderFile &headerFile)
{
	this->headerFile = headerFile;
}

/**
* @brief Returns header file of function.
*/
HeaderFile Function::getHeaderFile() const
{
	return headerFile;
}

} // namespace ctypes
} // namespace retdec
