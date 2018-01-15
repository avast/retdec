/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/basic_plain_getter.h
 * @brief Definition of BasicPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_BASIC_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_BASIC_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for basic information about file
 */
class BasicPlainGetter : public SimpleGetter
{
	public:
		BasicPlainGetter(FileInformation &fileInfo);
		virtual ~BasicPlainGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
