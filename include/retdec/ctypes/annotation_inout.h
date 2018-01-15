/**
* @file include/retdec/ctypes/annotation_inout.h
* @brief A representation of @c inout annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ANNOTATION_INOUT_H
#define RETDEC_CTYPES_ANNOTATION_INOUT_H

#include "retdec/ctypes/annotation.h"

namespace retdec {
namespace ctypes {

/**
* @brief A representation of @c inout annotation.
*/
class AnnotationInOut: public Annotation
{
	public:
		AnnotationInOut(const std::string &name): Annotation(name) {};
		static std::shared_ptr<AnnotationInOut> create(
			const std::shared_ptr<Context> &context,
			const std::string &name);

		virtual bool isInOut() const override;
};

} // namespace ctypes
} // namespace retdec

#endif
