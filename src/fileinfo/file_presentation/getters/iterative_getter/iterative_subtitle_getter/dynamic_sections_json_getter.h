/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/dynamic_sections_json_getter.h
 * @brief Definition of DynamicSectionsJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_DYNAMIC_SECTIONS_JSON_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_DYNAMIC_SECTIONS_JSON_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/iterative_subtitle_getter.h"

namespace fileinfo {

/**
 * Getter for dynamic sections
 */
class DynamicSectionsJsonGetter : public IterativeSubtitleGetter
{
	public:
		DynamicSectionsJsonGetter(FileInformation &fileInfo);
		virtual ~DynamicSectionsJsonGetter() override;

		virtual std::size_t getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const override;
		virtual bool getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const override;
		virtual bool getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const override;
};

} // namespace fileinfo

#endif
