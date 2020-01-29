/**
 * @file src/fileformat/types/visual_basic/visual_basic_object.cpp
 * @brief Class visual basic object.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/visual_basic/visual_basic_object.h"

namespace retdec {
namespace fileformat {

/**
 * Get name
 * @return name
 */
const std::string &VisualBasicObject::getName() const
{
	return name;
}

/**
 * Get methods
 * @return Object methods
 */
const std::vector<std::string> &VisualBasicObject::getMethods() const
{
	return methods;
}

/**
 * Get number of methods
 * @return number of methods
 */
std::size_t VisualBasicObject::getNumberOfMethods() const
{
	return methods.size();
}

/**
 * Set name
 * @param n Name to set
 */
void VisualBasicObject::setName(const std::string &n)
{
	name = n;
}

/**
 * Add method
 * @param method Method to add
 */
void VisualBasicObject::addMethod(const std::string &method)
{
	methods.push_back(method);
}

} // namespace fileformat
} // namespace retdec
