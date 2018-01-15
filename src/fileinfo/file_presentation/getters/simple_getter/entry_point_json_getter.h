/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/entry_point_json_getter.h
 * @brief Definition of EntryPointJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_ENTRY_POINT_JSON_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_ENTRY_POINT_JSON_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for information about entry point
 */
class EntryPointJsonGetter : public SimpleGetter
{
	public:
		EntryPointJsonGetter(FileInformation &fileInfo);
		virtual ~EntryPointJsonGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
