/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/header_plain_getter.h
 * @brief Definition of HeaderPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_HEADER_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_HEADER_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for information from file headers
 */
class HeaderPlainGetter : public SimpleGetter
{
	public:
		HeaderPlainGetter(FileInformation &fileInfo);
		virtual ~HeaderPlainGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
		void getFileFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const;
		void getDllFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const;
};

} // namespace fileinfo

#endif
