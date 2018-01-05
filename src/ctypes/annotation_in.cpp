/**
* @file src/ctypes/annotation_in.cpp
* @brief Implementation of @c in annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/annotation_in.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
* @brief Creates @c in annotation.
*
* @par Preconditions
*  - @a context is not null
*/
std::shared_ptr<AnnotationIn> AnnotationIn::create(
	const std::shared_ptr<Context> &context,
	const std::string &name)
{
	assert(context && "violated precondition - context cannot be null");

	auto annot = context->getAnnotation(name);
	if (annot && annot->isIn())
	{
		return std::static_pointer_cast<AnnotationIn>(annot);
	}

	std::shared_ptr<AnnotationIn> newAnnot(new AnnotationIn(name));
	context->addAnnotation(newAnnot);
	return newAnnot;
}

bool AnnotationIn::isIn() const
{
	return true;
}

} // namespace ctypes
} // namespace retdec
