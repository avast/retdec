/**
* @file include/retdec/ctypes/annotation_optional.h
* @brief A representation of @c optional annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ANNOTATION_OPTIONAL_H
#define RETDEC_CTYPES_ANNOTATION_OPTIONAL_H

#include "retdec/ctypes/annotation.h"

namespace retdec {
namespace ctypes {

/**
* @brief A representation of @c optional annotation.
*/
class AnnotationOptional: public Annotation
{
	public:
		AnnotationOptional(const std::string &name): Annotation(name) {};
		static std::shared_ptr<AnnotationOptional> create(
			const std::shared_ptr<Context> &context,
			const std::string &name);

		virtual bool isOptional() const override;
};

} // namespace ctypes
} // namespace retdec

#endif
