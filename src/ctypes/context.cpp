/**
* @file src/ctypes/context.cpp
* @brief Implementation of Context.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/annotation.h"
#include "retdec/ctypes/context.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/type.h"
#include "retdec/utils/container.h"

namespace retdec {
namespace ctypes {

/**
* @brief Checks if context contains function.
*
* @return True if context has function, false otherwise.
*/
bool Context::hasFunctionWithName(const std::string &name) const
{
	return retdec::utils::mapHasKey(functions, name);
}

/**
* @brief Returns function from context.
*
* @return Requested function. If it is not in context return @c nullptr.
*/
std::shared_ptr<Function> Context::getFunctionWithName(const std::string &name) const
{
	return retdec::utils::mapGetValueOrDefault(functions, name);
}

/**
* @brief Inserts new function to context.
*
* @par Preconditions
*  - @a function is not null
*
* Function with same name will be overwritten.
*/
void Context::addFunction(const std::shared_ptr<Function> &function)
{
	assert(function && "violated precondition - function cannot be null");

	functions.emplace(function->getName(), function);
}

/**
* @brief Checks if context contains function type.
*
* @return True if context has function type, false otherwise.
*
* @par Preconditions
*  - @a returnType is not null
*/
bool Context::hasFunctionType(
	const std::shared_ptr<Type> &returnType,
	const FunctionType::Parameters &parameters) const
{
	assert(returnType && "violated precondition - returnType cannot be null");

	return retdec::utils::mapHasKey(functionTypes, std::make_pair(returnType, parameters));
}

/**
* @brief Returns function type from context.
*
* @return Requested type. If it is not in context return @c nullptr.
*
* @par Preconditions
*  - @a returnType is not null
*/
std::shared_ptr<FunctionType> Context::getFunctionType(
	const std::shared_ptr<Type> &returnType,
	const FunctionType::Parameters &parameters) const
{
	assert(returnType && "violated precondition - returnType cannot be null");

	return retdec::utils::mapGetValueOrDefault(functionTypes, std::make_pair(returnType, parameters));
}

/**
* @brief Inserts new function type to context.
*
* @par Preconditions
*  - @a functionType is not null
*/
void Context::addFunctionType(const std::shared_ptr<FunctionType> &functionType)
{
	assert(functionType && "violated precondition - functionType cannot be null");

	auto returnType = functionType->getReturnType();
	auto key = std::make_pair(returnType, functionType->getParameters());
	functionTypes.emplace(key, functionType);
}

/**
* @brief Checks if context contains type with specific name.
*
* @return True if context has type, false otherwise.
*/
bool Context::hasNamedType(const std::string &name) const
{
	return retdec::utils::mapHasKey(namedTypes, name);
}

/**
* @brief Returns type with specific name from context.
*
* @return Requested type. If it is not in context return @c nullptr.
*/
std::shared_ptr<Type> Context::getNamedType(const std::string &name) const
{
	return retdec::utils::mapGetValueOrDefault(namedTypes, name);
}

/**
* @brief Inserts new type with specific name to context.
*
* @par Preconditions
*  - @a type is not null
*/
void Context::addNamedType(const std::shared_ptr<Type> &type)
{
	assert(type && "violated precondition - type cannot be null");

	namedTypes.emplace(type->getName(), type);
}

/**
* @brief Checks if context contains pointer type.
*
* @return True if context has pointer type, false otherwise.
*
* @par Preconditions
*  - @a pointedType is not null
*/
bool Context::hasPointerType(const std::shared_ptr<Type> &pointedType) const
{
	assert(pointedType && "violated precondition - pointedType cannot be null");

	return retdec::utils::mapHasKey(pointerTypes, pointedType);
}

/**
* @brief Returns pointerType from context.
*
* @return Requested pointerType. If it is not in context return @c nullptr.
*
* @par Preconditions
*  - @a pointedType is not null
*/
std::shared_ptr<PointerType> Context::getPointerType(
	const std::shared_ptr<Type> &pointedType) const
{
	assert(pointedType && "violated precondition - pointedType cannot be null");

	return retdec::utils::mapGetValueOrDefault(pointerTypes, pointedType);
}

/**
* @brief Inserts new pointerType with specific name to context.
*
* @par Preconditions
*  - @a pointerType is not null
*/
void Context::addPointerType(const std::shared_ptr<PointerType> &pointerType)
{
	assert(pointerType && "violated precondition - pointerType cannot be null");

	pointerTypes.emplace(pointerType->getPointedType(), pointerType);
}

/**
* @brief Checks if context contains array type.
*
* @return True if context has array type, false otherwise.
*
* @par Preconditions
*  - @a elementType is not null
*/
bool Context::hasArrayType(const std::shared_ptr<Type> &elementType,
	const ArrayType::Dimensions &dimensions) const
{
	assert(elementType && "violated precondition - elementType cannot be null");

	return retdec::utils::mapHasKey(arrayTypes, std::make_pair(elementType, dimensions));
}

/**
* @brief Returns array type from context.
*
* @return Requested pointerType. If it is not in context return @c nullptr.
*
* @par Preconditions
*  - @a elementType is not null
*/
std::shared_ptr<ArrayType> Context::getArrayType(const std::shared_ptr<Type> &elementType,
	const ArrayType::Dimensions &dimensions) const
{
	assert(elementType && "violated precondition - elementType cannot be null");

	return retdec::utils::mapGetValueOrDefault(arrayTypes, std::make_pair(elementType, dimensions));
}

/**
* @brief Adds array type to context.
*
* @par Preconditions
*  - @a arrayType is not null
*/
void Context::addArrayType(const std::shared_ptr<ArrayType> &arrayType)
{
	assert(arrayType && "violated precondition - arrayType cannot be null");

	auto elementType = arrayType->getElementType();
	auto key = std::make_pair(elementType, arrayType->getDimensions());
	arrayTypes.emplace(key, arrayType);
}

/**
* @brief Checks if context contains annotation.
*
* @return True if context has annotation, false otherwise.
*/
bool Context::hasAnnotation(const std::string &name) const
{
	return retdec::utils::mapHasKey(annotations, name);
}

/**
* @brief Returns annotation from context.
*
* @return Requested annotation. If it is not in context return @c nullptr.
*/
std::shared_ptr<Annotation> Context::getAnnotation(const std::string &name) const
{
	return retdec::utils::mapGetValueOrDefault(annotations, name);
}

/**
* @brief Adds annotation to context.
*/
void Context::addAnnotation(const std::shared_ptr<Annotation> &annot)
{
	annotations.emplace(annot->getName(), annot);
}

} // namespace ctypes
} // namespace retdec
