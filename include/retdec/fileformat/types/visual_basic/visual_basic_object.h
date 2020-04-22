/**
 * @file include/retdec/fileformat/types/visual_basic/visual_basic_object.h
 * @brief Class for visual basic object.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_OBJECT_H
#define RETDEC_FILEFORMAT_TYPES_VISUAL_BASIC_VISUAL_BASIC_OBJECT_H

#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * Class for visual basic information
 */
class VisualBasicObject
{
	private:
		std::string name;
		std::vector<std::string> methods;
	public:
		/// @name Getters
		/// @{
		const std::string &getName() const;
		const std::vector<std::string> &getMethods() const;
		std::size_t getNumberOfMethods() const;
		/// @}

		/// @name Setters
		/// @{
		void setName(const std::string &n);
		/// @}

		/// @name Other methods
		/// @{
		void addMethod(const std::string &method);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
