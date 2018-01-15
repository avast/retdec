/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/dotnet_plain_getter.h
 * @brief Definition of DotnetPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_DOTNET_PLAIN_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_SIMPLE_GETTER_DOTNET_PLAIN_GETTER_H

#include "fileinfo/file_presentation/getters/simple_getter/simple_getter.h"

namespace fileinfo {

/**
 * Getter for information about .NET
 */
class DotnetPlainGetter : public SimpleGetter
{
	public:
		DotnetPlainGetter(FileInformation &fileInfo);
		virtual ~DotnetPlainGetter() override;

		virtual std::size_t loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const override;
};

} // namespace fileinfo

#endif
