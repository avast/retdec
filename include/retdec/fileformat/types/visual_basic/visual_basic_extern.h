/**
 * @file include/retdec/fileformat/types/visual_basic/visual_basic_extern.h
 * @brief Class for visual basic extern.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_EXTERN_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_EXTERN_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * Class for visual basic information
 */
class VisualBasicExtern
{
	private:
		std::string moduleName;
		std::string apiName;
	public:
		/// @name Getters
		/// @{
		const std::string &getModuleName() const;
		const std::string &getApiName() const;
		/// @}

		/// @name Setters
		/// @{
		void setModuleName(const std::string &mName);
		void setApiName(const std::string &aName);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
