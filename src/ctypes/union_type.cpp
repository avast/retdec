/**
* @file src/ctypes/union_type.cpp
* @brief Implementation of UnionType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new union type.
*
* See @c create() for more information.
*/
UnionType::UnionType(const std::string &name, const Members &members) :
	CompositeType(name, members) {}

/**
* @brief Creates union type.
*
* @param context Storage for already created functions, types.
* @param name Name of new type.
* @param members Items of union.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new union type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<UnionType> UnionType::create(
	const std::shared_ptr<Context> &context,
	const std::string &name,
	const Members &members)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isUnion())
	{
		return std::static_pointer_cast<UnionType>(type);
	}

	std::shared_ptr<UnionType> newType(new UnionType(name, members));
	context->addNamedType(newType);
	return newType;
}

/**
* Returns @c true when Type is union, @c false otherwise.
*/
bool UnionType::isUnion() const
{
	return true;
}

void UnionType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<UnionType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
