/**
* @file src/ctypes/reference_type.cpp
* @brief Implementation of ReferenceType.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/context.h"
#include "retdec/ctypes/reference_type.h"
#include "retdec/ctypes/visitor.h"

namespace retdec {
namespace ctypes {

/**
 * @brief Constructs new reference type.
 */
ReferenceType::ReferenceType(
	const std::shared_ptr<Type> &referencedType,
	unsigned int bitWidth) :
	Type("", bitWidth), referencedType(referencedType) {}

/**
 * Creates reference type.
 *
 * @param context Storage for already created functions, types.
 * @param referencedType Type that reference references.
 * @param bitWidth Number of bits used by this type.
 *
 * @par Preconditions
 *  - @a context is not null
 *  - @a referencedType is not null
 *
 * Does not create new pointer type, if one
 * has already been created and stored in @c context.
 */
std::shared_ptr<ReferenceType> ReferenceType::create(
	const std::shared_ptr<Context> &context,
	const std::shared_ptr<Type> &referencedType,
	unsigned int bitWidth)
{
	assert(context && "violated precondition - context cannot be null");
	assert(referencedType && "violated precondition - referencedType cannot be null");

	auto type = context->getReferenceType(referencedType);
	if (type) {
		return type;
	}

	std::shared_ptr<ReferenceType> newType(new ReferenceType(referencedType, bitWidth));
	context->addReferenceType(newType);
	return newType;
}

/**
 * @brief Returns referencedType.
 */
std::shared_ptr<Type> ReferenceType::getReferencedType() const
{
	return referencedType;
}

/**
 * Returns @c true when Type is pointer, @c false otherwise.
 */
bool ReferenceType::isReference() const
{
	return true;
}

void ReferenceType::accept(Visitor *v)
{
	v->visit(std::static_pointer_cast<ReferenceType>(shared_from_this()));
}

} // namespace ctypes
} // namespace retdec