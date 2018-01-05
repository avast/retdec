/**
* @file src/ctypes/module.cpp
* @brief Implementation of Module.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/module.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new module.
*/
Module::Module(const std::shared_ptr<Context> &context):
	context(context) {}

/**
* @brief Checks if module contains function.
*/
bool Module::hasFunctionWithName(const std::string &name) const
{
	return retdec::utils::mapHasKey(functions, name);
}

/**
* @brief Returns function from module.
*
* @return Requested function. If it is not in module return @c null.
*/
std::shared_ptr<Function> Module::getFunctionWithName(const std::string &name) const
{
	return retdec::utils::mapGetValueOrDefault(functions, name);
}

/**
* @brief Adds new function to module.
*
* @par Preconditions
*  - @a function is not null
*/
void Module::addFunction(const std::shared_ptr<Function> &function)
{
	assert(function && "violated precondition - function cannot be null");

	functions.emplace(function->getName(), function);
}

/*
* @brief Returns container of type information used in module's functions.
*
* Use this member function ONLY if you are sure what you are doing.
* Otherwise, do not use it. It is meant to be used only by parsers and should not
* be used in user code.
*/
std::shared_ptr<Context> Module::getContext() const
{
	return context;
}

} // namespace ctypes
} // namespace retdec
