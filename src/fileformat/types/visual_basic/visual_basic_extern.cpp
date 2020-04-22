/**
 * @file src/fileformat/types/visual_basic/visual_basic_extern.cpp
 * @brief Class visual basic extern.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/visual_basic/visual_basic_extern.h"

namespace retdec {
namespace fileformat {

/**
 * Get module name
 * @return Module name
 */
const std::string &VisualBasicExtern::getModuleName() const
{
	return moduleName;
}

/**
 * Get api name
 * @return Api name
 */
const std::string &VisualBasicExtern::getApiName() const
{
	return apiName;
}

/**
 * Set module name
 * @param mName Module name to set
 */
void VisualBasicExtern::setModuleName(const std::string &mName)
{
	moduleName = mName;
}

/**
 * Set api name
 * @param aName Api name to set
 */
void VisualBasicExtern::setApiName(const std::string &aName)
{
	apiName = aName;
}

} // namespace fileformat
} // namespace retdec
