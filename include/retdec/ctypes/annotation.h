/**
* @file include/retdec/ctypes/annotation.h
* @brief A representation of type's annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_ANNOTATION_H
#define RETDEC_CTYPES_ANNOTATION_H

#include <memory>
#include <string>

namespace retdec {
namespace ctypes {

class Context;

/**
* @brief A representation of annotation.
*
* Derived class should override @c isX() method according to annotation type.
*/
class Annotation
{
	public:
		virtual ~Annotation();

		virtual bool isIn() const;
		virtual bool isOut() const;
		virtual bool isInOut() const;
		virtual bool isOptional() const;

		const std::string &getName() const;

	protected:
		explicit Annotation(const std::string &name);

	private:
		std::string name;
};

} // namespace ctypes
} // namespace retdec

#endif
