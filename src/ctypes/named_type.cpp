/**
* @file src/ctypes/named_type.cpp
* @brief Implementation of custom types.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/named_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
 * @brief Constructs new NamedType
 */
NamedType::NamedType(const std::string &name) : Type(name, 0) {}

/**
* @brief Creates named type.
*
* @param context Storage for already created functions, types.
* @param name Name of new named type.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new name type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<NamedType> NamedType::create(
	const std::shared_ptr<Context> &context,
	const std::string &name)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isNamed()) {
		return std::static_pointer_cast<NamedType>(type);
	}

	std::shared_ptr<NamedType> newType(new NamedType(name));
	context->addNamedType(newType);
	return newType;
}

/**
* Returns @c true when Type is class, @c false otherwise.
*/
bool NamedType::isNamed() const
{
	return true;
}

void NamedType::accept(Visitor *v)
{
	v->visit(std::static_pointer_cast<NamedType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
