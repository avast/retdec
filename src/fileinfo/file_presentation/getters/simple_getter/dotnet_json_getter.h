/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/dotnet_json_getter.h
 * @brief Definition of DotnetJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_DOTNET_JSON_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_DOTNET_JSON_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for information about .NET
 */
class DotnetJsonGetter : public SimpleGetter
{
	public:
		DotnetJsonGetter(FileInformation &fileInfo);
		virtual ~DotnetJsonGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
