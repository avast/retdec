/**
* @file include/retdec/ctypes/annotation_in.h
* @brief A representation of @c in annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ANNOTATION_IN_H
#define RETDEC_CTYPES_ANNOTATION_IN_H

#include "retdec/ctypes/annotation.h"

namespace retdec {
namespace ctypes {

/**
* @brief A representation of @c in annotation.
*/
class AnnotationIn: public Annotation
{
	public:
		AnnotationIn(const std::string &name): Annotation(name) {};
		static std::shared_ptr<AnnotationIn> create(
			const std::shared_ptr<Context> &context,
			const std::string &name);

		virtual bool isIn() const override;
};

} // namespace ctypes
} // namespace retdec

#endif
