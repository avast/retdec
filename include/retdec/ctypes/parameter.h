/**
* @file include/retdec/ctypes/parameter.h
* @brief A representation of a function parameter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPES_PARAMETER_H
#define RETDEC_CTYPES_PARAMETER_H

#include <memory>
#include <set>
#include <string>

namespace retdec {
namespace ctypes {

class Annotation;
class Type;

/**
* @brief A representation of a function parameter.
*/
class Parameter
{
	public:
		using Annotations = std::set<std::shared_ptr<Annotation>>;
		using annotation_iterator = Annotations::iterator;
		using const_annotation_iterator = Annotations::const_iterator;

	public:
		Parameter(
			const std::string &name,
			const std::shared_ptr<Type> &type,
			const Annotations &annotations = {});

		const std::string &getName() const;
		std::shared_ptr<Type> getType() const;

		/// @name Parameter annotations.
		/// @{
		annotation_iterator annotation_begin();
		const_annotation_iterator annotation_begin() const;
		annotation_iterator annotation_end();
		const_annotation_iterator annotation_end() const;

		bool isIn() const;
		bool isOut() const;
		bool isInOut() const;
		bool isOptional() const;
		/// @}

		bool operator==(const Parameter &other) const;
		bool operator!=(const Parameter &other) const;

	private:
		/// Pointer to Annotation's member functions.
		using AnnotationTypeHandler = bool (Annotation::*)() const;

		bool hasAnnotationOfType(const AnnotationTypeHandler &annotationType) const;

	private:
		std::string name;
		std::shared_ptr<Type> type;
		Annotations annotations;
};

} // namespace ctypes
} // namespace retdec

#endif
