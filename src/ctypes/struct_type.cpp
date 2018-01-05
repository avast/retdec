/**
* @file src/ctypes/struct_type.cpp
* @brief Implementation of StructType.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new struct type.
*
* See @c create() for more information.
*/
StructType::StructType(const std::string &name, const Members &members) :
	CompositeType(name, members) {}

/**
* @brief Creates struct type.
*
* @param context Storage for already created functions, types.
* @param name Name of new type.
* @param members Items of struct.
*
* @par Preconditions
*  - @a context is not null
*
* Does not create new struct type, if one
* has already been created and stored in @c context.
*/
std::shared_ptr<StructType> StructType::create(
	const std::shared_ptr<Context> &context,
	const std::string &name, const Members &members)
{
	assert(context && "violated precondition - context cannot be null");

	auto type = context->getNamedType(name);
	if (type && type->isStruct())
	{
		return std::static_pointer_cast<StructType>(type);
	}

	std::shared_ptr<StructType> newType(new StructType(name, members));
	context->addNamedType(newType);
	return newType;
}

/**
* Returns @c true when Type is struct, @c false otherwise.
*/
bool StructType::isStruct() const
{
	return true;
}

void StructType::accept(Visitor *v) {
	v->visit(std::static_pointer_cast<StructType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec
