/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/simple_getter.h
 * @brief Definition of SimpleGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_SIMPLE_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_SIMPLE_GETTER_H

#include "fileinfo/file_information/file_information.h"

namespace fileinfo {

/**
 * Abstract class for loading information about file
 */
class SimpleGetter
{
	protected:
		FileInformation &fileinfo;
	public:
		SimpleGetter(FileInformation &fileInfo);
		virtual ~SimpleGetter();

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const = 0;
};

} // namespace fileinfo

#endif
