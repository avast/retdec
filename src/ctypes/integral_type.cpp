/**
* @file src/ctypes/integral_type.cpp
* @brief Implementation of IntegralType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new integral type.
*
* See @c create() for more information.
*/
IntegralType::IntegralType(const std::string &name, unsigned bitWidth, Signess signess):
	Type(name, bitWidth), signess(signess) {}

/**
* @brief Creates integral type.
*
* @param context Storage for already created functions, types.
* @param name Name of new type.
* @param bitWidth Number of bits used by this type.
* @param signess Sign of type.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new integral type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<IntegralType> IntegralType::create(const std::shared_ptr<Context> &context,
	const std::string &name, unsigned bitWidth, Signess signess)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isIntegral())
	{
		return std::static_pointer_cast<IntegralType>(type);
	}

	std::shared_ptr<IntegralType> newType(new IntegralType(name, bitWidth, signess));
	context->addNamedType(newType);
	return newType;
}

/**
* @brief Returns true for signed types, false otherwise.
*/
bool IntegralType::isSigned() const
{
	return signess == Signess::Signed;
}

/**
* @brief Returns true for unsigned types, false otherwise.
*/
bool IntegralType::isUnsigned() const
{
	return !isSigned();
}

/**
* Returns @c true when Type is integral, @c false otherwise.
*/
bool IntegralType::isIntegral() const
{
	return true;
}

void IntegralType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<IntegralType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
