/**
* @file src/ctypes/annotation.cpp
* @brief Implementation of annotation.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/ctypes/annotation.h"

namespace retdec {
namespace ctypes {

/**
* @brief Constructs a new annotation.
*
* See @c create() for more information.
*/
Annotation::Annotation(const std::string &name):
	name(name) {}

/**
* @brief Destructs the annotations.
*/
Annotation::~Annotation() = default;

bool Annotation::isIn() const
{
	return false;
}

bool Annotation::isOut() const
{
	return false;
}

bool Annotation::isInOut() const
{
	return false;
}

bool Annotation::isOptional() const
{
	return false;
}

/**
* @brief Returns annotation's name.
*/
const std::string &Annotation::getName() const
{
	return name;
}

} // namespace ctypes
} // namespace retdec
