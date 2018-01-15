/**
* @file src/ctypes/annotation_optional.cpp
* @brief Implementation of @c optional annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/annotation_optional.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
* @brief Creates @c optional annotation.
*
* @par Preconditions
*  - @a context is not null
*/
std::shared_ptr<AnnotationOptional> AnnotationOptional::create(
	const std::shared_ptr<Context> &context,
	const std::string &name)
{
	assert(context && "violated precondition - context cannot be null");

	auto annot = context->getAnnotation(name);
	if (annot && annot->isOptional())
	{
		return std::static_pointer_cast<AnnotationOptional>(annot);
	}

	std::shared_ptr<AnnotationOptional> newAnnot(new AnnotationOptional(name));
	context->addAnnotation(newAnnot);
	return newAnnot;
}

bool AnnotationOptional::isOptional() const
{
	return true;
}

} // namespace ctypes
} // namespace retdec
