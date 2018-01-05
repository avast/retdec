/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/import_table_json_getter.h
 * @brief Definition of ImportTableJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_IMPORT_TABLE_JSON_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_IMPORT_TABLE_JSON_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/iterative_subtitle_getter.h"

namespace fileinfo {

/**
 * Getter for import table
 */
class ImportTableJsonGetter : public IterativeSubtitleGetter
{
	public:
		ImportTableJsonGetter(FileInformation &fileInfo);
		virtual ~ImportTableJsonGetter() override;

		virtual std::size_t getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const override;
		virtual bool getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const override;
		virtual bool getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const override;
};

} // namespace fileinfo

#endif
