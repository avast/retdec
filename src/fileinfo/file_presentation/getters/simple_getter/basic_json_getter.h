/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/basic_json_getter.h
 * @brief Definition of BasicJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_BASIC_JSON_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_BASIC_JSON_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for basic information about file
 */
class BasicJsonGetter : public SimpleGetter
{
	public:
		BasicJsonGetter(FileInformation &fileInfo);
		virtual ~BasicJsonGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
