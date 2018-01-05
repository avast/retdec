/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/iterative_subtitle_getter.h
 * @brief Definition of IterativeSubtitleGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_ITERATIVE_SUBTITLE_GETTER_H
#define FILEINFO_FILE_PRESENTATION_GETTERS_ITERATIVE_GETTER_ITERATIVE_SUBTITLE_GETTER_ITERATIVE_SUBTITLE_GETTER_H

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_getter.h"

namespace fileinfo {

/**
 * Abstract class for loading information about file.
 *
 * This class enable iterative queries to a set of items
 * (e.g. queries to symbols from symbol tables).
 */
class IterativeSubtitleGetter : public IterativeGetter
{
	protected:
		std::string header;   ///< title of presented structures
		std::string subtitle; ///< subtitle of presented record
	public:
		IterativeSubtitleGetter(FileInformation &fileInfo);
		virtual ~IterativeSubtitleGetter() override;

		/// @name Getters
		/// @{
		void getHeader(std::string &structsHeader) const;
		void getSubtitle(std::string &subTitle) const;
		/// @}

		/// @name Pure virtual methods
		/// @{
		virtual bool getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const = 0;
		/// @}
};

} // namespace fileinfo

#endif
