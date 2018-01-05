/**
* @file src/ctypes/parameter.cpp
* @brief Implementation of Parameter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/annotation.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypes/type.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new parameter.
*/
Parameter::Parameter(const std::string &name, const std::shared_ptr<Type> &type,
	const Annotations &annotations):
	name(name), type(type), annotations(annotations) {}

/**
* @brief Returns parameter's name.
*/
const std::string &Parameter::getName() const
{
	return name;
}

/**
* @brief Returns parameter's type.
*/
std::shared_ptr<Type> Parameter::getType() const
{
	return type;
}

/**
* @brief Returns an iterator to the annotation.
*/
Parameter::annotation_iterator Parameter::annotation_begin()
{
	return annotations.begin();
}

/**
* @brief Returns a constant iterator to the annotation.
*/
Parameter::const_annotation_iterator Parameter::annotation_begin() const
{
	return annotations.begin();
}

/**
* @brief Returns an iterator past the last annotation.
*/
Parameter::annotation_iterator Parameter::annotation_end()
{
	return annotations.end();
}

/**
* @brief Returns a constant iterator past the last annotation.
*/
Parameter::const_annotation_iterator Parameter::annotation_end() const
{
	return annotations.end();
}

bool Parameter::hasAnnotationOfType(const AnnotationTypeHandler &annotationType) const
{
	for (const auto &a: annotations)
	{
		if (((*a).*annotationType)())
		{
			return true;
		}
	}
	return false;
}

/**
* @brief Returns true when parameter is input, false otherwise.
*/
bool Parameter::isIn() const
{
	return hasAnnotationOfType(&Annotation::isIn);
}

/**
* @brief Returns true when parameter is output, false otherwise.
*/
bool Parameter::isOut() const
{
	return hasAnnotationOfType(&Annotation::isOut);
}

/**
* @brief Returns true when parameter will be changed by the function, false otherwise.
*/
bool Parameter::isInOut() const
{
	return hasAnnotationOfType(&Annotation::isInOut);
}

/**
* @brief Returns true when parameter may be @c null, false otherwise.
*/
bool Parameter::isOptional() const
{
	return hasAnnotationOfType(&Annotation::isOptional);
}

bool Parameter::operator==(const Parameter &other) const
{
	return name == other.name && type == other.type;
}

bool Parameter::operator!=(const Parameter &other) const
{
	return !(*this == other);
}

} // namespace ctypes
} // namespace retdec
