/**
* @file src/ctypes/typedefed_type.cpp
* @brief Implementation of TypedefedType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new typedefed type.
*/
TypedefedType::TypedefedType(const std::string &name,
	const std::shared_ptr<Type> &aliasedType):
	Type(name, 0), aliasedType(aliasedType) {}

/**
* @brief Creates typedefed type.
*
* @param context Storage for already created functions, types.
* @param name Name of new type.
* @param aliasedType Type, that this typedef stands for.
*
* @par Preconditions
*  - @a context is not null
*  - @a aliasedType is not null
*
* Does not create new typedefed type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<TypedefedType> TypedefedType::create(
	const std::shared_ptr<Context> &context,
	const std::string &name,
	const std::shared_ptr<Type> &aliasedType)
{
	assert(context && "violated precondition - context cannot be null");
	assert(aliasedType && "violated precondition - aliasedType cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isTypedef())
	{
		return std::static_pointer_cast<TypedefedType>(type);
	}

	std::shared_ptr<TypedefedType> newType(new TypedefedType(name, aliasedType));
	context->addNamedType(newType);
	return newType;
}

/**
* @brief Returns type that typedef stands for.
*
* Aliased type for @c MyInt in
* @code
* typedef int MyInt;
* @endcode
* is @c int
*
* Aliased type for @c MySecondInt in
* @code
* typedef int MyInt;
* typedef MyInt MySecondInt;
* @endcode
* is @c MyInt
*
*/
std::shared_ptr<Type> TypedefedType::getAliasedType() const
{
	return aliasedType;
}

/**
* @brief Returns real type that typedef stands for.
*
* If aliased type is typedefed type, get its real type.
*
* Real type for @c MySecondint in
* @code
* typedef int MyInt;
* typedef MyInt MySecondInt;
* @endcode
* is @c int
*/
std::shared_ptr<Type> TypedefedType::getRealType() const
{
	auto alias = aliasedType;
	while (alias->isTypedef())
	{
		alias = std::static_pointer_cast<TypedefedType>(alias)->aliasedType;
	}
	return alias;
}

/**
* Returns @c true when Type is typedef, @c false otherwise.
*/
bool TypedefedType::isTypedef() const
{
	return true;
}

void TypedefedType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<TypedefedType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
