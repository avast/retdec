/**
* @file src/ctypes/annotation_out.cpp
* @brief Implementation of @c out annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cassert>

#include "retdec/ctypes/annotation_out.h"
#include "retdec/ctypes/context.h"

namespace retdec {
namespace ctypes {

/**
* @brief Creates @c out annotation.
*
* @par Preconditions
*  - @a context is not null
*/
std::shared_ptr<AnnotationOut> AnnotationOut::create(
	const std::shared_ptr<Context> &context,
	const std::string &name)
{
	assert(context && "violated precondition - context cannot be null");

	auto annot = context->getAnnotation(name);
	if (annot && annot->isOut())
	{
		return std::static_pointer_cast<AnnotationOut>(annot);
	}

	std::shared_ptr<AnnotationOut> newAnnot(new AnnotationOut(name));
	context->addAnnotation(newAnnot);
	return newAnnot;
}

bool AnnotationOut::isOut() const
{
	return true;
}

} // namespace ctypes
} // namespace retdec
