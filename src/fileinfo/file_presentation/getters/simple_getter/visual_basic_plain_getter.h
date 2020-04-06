/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/visual_basic_plain_getter.h
 * @brief Definition of VisualBasicPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_VISUAL_BASIC_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_VISUAL_BASIC_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace retdec {
namespace fileinfo {

/**
 * Getter for information about visual basic
 */
class VisualBasicPlainGetter : public SimpleGetter
{
	public:
		VisualBasicPlainGetter(FileInformation &fileInfo);

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo
} // namespace retdec

#endif
