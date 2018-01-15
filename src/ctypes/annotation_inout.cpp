/**
* @file src/ctypes/annotation_inout.cpp
* @brief Implementation of @c inout annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/annotation_inout.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
* @brief Creates @c inout annotation.
*
* @par Preconditions
*  - @a context is not null
*/
std::shared_ptr<AnnotationInOut> AnnotationInOut::create(
	const std::shared_ptr<Context> &context,
	const std::string &name)
{
	assert(context && "violated precondition - context cannot be null");

	auto annot = context->getAnnotation(name);
	if (annot && annot->isInOut())
	{
		return std::static_pointer_cast<AnnotationInOut>(annot);
	}

	std::shared_ptr<AnnotationInOut> newAnnot(new AnnotationInOut(name));
	context->addAnnotation(newAnnot);
	return newAnnot;
}

bool AnnotationInOut::isInOut() const
{
	return true;
}

} // namespace ctypes
} // namespace retdec
